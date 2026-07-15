pub(crate) mod ops;
pub(crate) mod strategies;

use strategies::{FastStrategy, FilterStrategy, StatTrackStrategy};
pub use strategies::{FilterPreProcess, GameStats};

use crate::{
    LOG_ONLY,
    commands::{CommandContext, CommandErr, ReplHandle, settings::Settings},
    impl_rate_limit_config,
    models::{
        cli::{Filters, Region, Source},
        json_data::{GetInfo, IpLocation, ServerInfo},
    },
    non_critical_err, parse_hostname,
    utils::{
        caching::ContCode,
        display::{
            DisplayCountOf, DisplayServerCount, SOURCE_HMW, SingularPlural, indicator::Spinner,
        },
        limiter::RateLimiter,
        main_thread_state,
        request::{ResponseErr, STATUS_OK, client_with_timeout, serde_deserialize},
    },
};

use std::{
    cell::Cell,
    collections::HashSet,
    fmt::Display,
    fs::File,
    io::{self, Write},
    net::{AddrParseError, IpAddr, SocketAddr, ToSocketAddrs},
    time::Duration,
};

use repl_oxide::ansi_code::{CLEAR_LINE, GREEN, RED, RESET, YELLOW};
use reqwest::Client;
use tracing::{error, info, instrument, trace, warn};

const LOCATION_SERVICE_PROVIDER: &str = "ip-api.com";
const BATCH_LOCATION_URL: &str = "http://ip-api.com/batch?fields=message,continentCode";
impl_rate_limit_config!(Location, 15, Duration::from_secs(60));

const FAVORITES_LOC: &str = "players2";
const FAVORITES: &str = "favourites.json";

pub(crate) const DEFAULT_SOURCES: [Source; 2] = [Source::Iw4Master, Source::HmwMaster];
const DEFAULT_H2M_SERVER_CAP: usize = 100;

const RETRY_TIME_SCALE: Duration = Duration::from_millis(800);

const LOCAL_HOST: &str = "localhost";

pub(crate) const GAME_ID: [&str; 2] = ["H2M", "HMW"];
pub(crate) const H2M_ID: &str = GAME_ID[0];
pub(crate) const HMW_ID: &str = GAME_ID[1];

pub(crate) mod continent {
    use super::ContCode;

    pub(crate) const COUNT: usize = 4;
    pub(crate) const NA_CODE: [ContCode; 1] = [*b"NA"];
    pub(crate) const SA_CODE: [ContCode; 1] = [*b"SA"];
    pub(crate) const EU_CODES: [ContCode; 2] = [*b"EU", *b"AF"];
    pub(crate) const APAC_CODES: [ContCode; 2] = [*b"AS", *b"OC"];
}

fn serialize_json_ips(
    f: &mut std::fs::File,
    mut ips: impl Iterator<Item = (SocketAddr, u8)>,
) -> io::Result<()> {
    let Some((first, _)) = ips.next() else {
        return write!(f, "[]");
    };

    write!(f, "[\"{first}\"")?;
    for (ip, _) in ips {
        write!(f, ",\"{ip}\"")?;
    }
    write!(f, "]")
}

#[instrument(name = "filter", level = "trace", skip_all)]
pub(super) async fn build_favorites(
    ctx: &CommandContext,
    repl: &mut ReplHandle,
    args: Option<Filters>,
) -> Result<bool, CommandErr> {
    let args = args.unwrap_or_default();
    let version = ctx.game_version().unwrap_or(1.0);

    let mut favorites_path = ctx.get_exe_dir().join(FAVORITES_LOC);
    match favorites_path.try_exists() {
        Ok(true) => (),
        Ok(false) => {
            std::fs::create_dir(&favorites_path).map_err(|err| {
                non_critical_err!("Could not create missing {FAVORITES_LOC} directory, err: {err}")
            })?;
            info!("\"players2\" folder is missing, a new one was created");
        }
        Err(err) => {
            return Err(non_critical_err!(
                "Could not confirm the existence of \"players2\" folder: {err}"
            ));
        }
    }

    favorites_path.push(FAVORITES);
    let mut favorites_json = File::create(&favorites_path)
        .map_err(|err| non_critical_err!("Could not create {FAVORITES}, err: {err}"))?;

    let spinner = Spinner::new(String::new());

    let limit = args
        .limit
        .unwrap_or(if version < 1.0 { DEFAULT_H2M_SERVER_CAP } else { 10000 });

    if version < 1.0 && limit >= DEFAULT_H2M_SERVER_CAP {
        println!(
            "{CLEAR_LINE}{YELLOW}\
            NOTE: Currently the in game server browser breaks when you add more than 100 servers to favorites\
            {RESET}"
        )
    }

    let mut filter = filter_server_list(repl, args, ctx.settings, spinner).await?;

    if filter.duplicates != 0 {
        println!(
            "{CLEAR_LINE}{YELLOW}{}{RESET} duplicate {} not included",
            filter.duplicates,
            SingularPlural(filter.duplicates, "server was", "servers were")
        );
    }

    println!(
        "{CLEAR_LINE}{} match the parameters in the current query",
        DisplayServerCount(filter.servers.len(), GREEN)
    );

    let ips_saved = if filter.servers.len() > limit {
        if !filter.sorted {
            filter
                .servers
                .sort_unstable_by_key(|&(_, clients)| std::cmp::Reverse(clients));
        }
        limit
    } else {
        filter.servers.len()
    };

    serialize_json_ips(
        &mut favorites_json,
        filter.servers.into_iter().take(ips_saved),
    )
    .map_err(|err| non_critical_err!("Could not write to {FAVORITES}, err: {err}"))?;

    println!(
        "{GREEN}{FAVORITES} updated with {}{RESET}",
        DisplayCountOf(ips_saved, "entry", "entries")
    );

    Ok(filter.cache_modified)
}

pub(crate) struct FilterData {
    /// `(addr, clients)`\
    /// If servers are _always_ sorted client computations can be omitted
    servers: Vec<(SocketAddr, u8)>,
    sorted: bool,
    duplicates: usize,
    cache_modified: bool,
}

pub(crate) enum RegionContainer {
    Set(HashSet<ContCode>),
    Vec(Vec<ContCode>),
}

impl RegionContainer {
    pub(crate) fn contains(&self, region: &ContCode) -> bool {
        match self {
            RegionContainer::Set(hash_set) => hash_set.contains(region),
            RegionContainer::Vec(items) => items.contains(region),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            RegionContainer::Set(hash_set) => hash_set.len(),
            RegionContainer::Vec(items) => items.len(),
        }
    }
}

impl Region {
    fn to_bytes(self) -> &'static [ContCode] {
        match self {
            Region::Apac => &continent::APAC_CODES,
            Region::EU => &continent::EU_CODES,
            Region::NA => &continent::NA_CODE,
            Region::SA => &continent::SA_CODE,
        }
    }

    fn to_byte_set(regions: &[Region]) -> RegionContainer {
        RegionContainer::Set(
            regions
                .iter()
                .copied()
                .flat_map(Region::to_bytes)
                .copied()
                .collect(),
        )
    }
}

impl Filters {
    fn need_get_info_data(&self) -> bool {
        self.excludes.is_some()
            || self.includes.is_some()
            || self.player_min.is_some()
            || self.team_size_max.is_some()
            || self.with_bots | self.without_bots | !self.include_unresponsive
    }

    /// Possible to execute filters using data found from the iw4 master server endpoint
    /// see [`ServerInfo`] for included fields.
    fn can_use_iw4m_data(&self) -> bool {
        !self.with_bots && !self.without_bots && self.include_unresponsive
    }

    fn regions(&self, settings: Settings) -> Option<RegionContainer> {
        self.region
            .as_deref()
            .map(Region::to_byte_set)
            .or_else(|| settings.regions())
    }
}

#[instrument(level = "trace", skip_all)]
async fn filter_server_list(
    repl: &mut ReplHandle,
    args: Filters,
    settings: Settings,
    spinner: Spinner,
) -> Result<FilterData, CommandErr> {
    let sources = args
        .source
        .as_deref()
        .map(|user_sources| user_sources.iter().copied().collect::<HashSet<_>>());

    spinner.update_message(format!(
        "Retrieving master {}",
        SingularPlural(
            sources
                .as_ref()
                .map(HashSet::len)
                .unwrap_or(DEFAULT_SOURCES.len()),
            "server",
            "servers"
        )
    ));

    let client = client_with_timeout(10);

    if args.stats {
        StatTrackStrategy::execute(repl, client, args, settings, sources, spinner).await
    } else {
        FastStrategy::execute(repl, client, args, settings, sources, spinner).await
    }
}

#[derive(Debug)]
pub struct Server {
    pub source: Sourced,
    pub info: GetInfo,
}

impl From<HostMeta> for Server {
    /// Real source is `Sourced::Iw4`  
    /// Source kind is modified to avoid cloning `ServerInfo` fields into the desired `GetInfo`
    fn from(value: HostMeta) -> Self {
        Server {
            info: GetInfo {
                clients: value.server.clients,
                max_clients: value.server.max_clients,
                // game_name: value.server.game,
                game_type: value.server.game_type.into(),
                host_name: value.server.host_name,
                map_name: value.server.map.into(),
                ..Default::default()
            },
            source: Sourced::Iw4Cached(value.resolved_addr),
        }
    }
}

pub(crate) struct GetInfoMetaData {
    msg: String,
    display_url: bool,
    display_socket_addr: bool,
    display_source: bool,
    retries: u8,
    pub(crate) url: String,
    pub(crate) meta: Sourced,
}

macro_rules! set_flag {
    ($(#[$attr:meta])* $name:ident, $field:ident, $value:literal) => {
        $(#[$attr])*
        #[inline]
        pub(crate) fn $name(&mut self) -> &mut Self {
            self.$field = $value;
            self
        }
    };
}

#[expect(dead_code)]
impl GetInfoMetaData {
    fn new(meta: Sourced, server_info_endpoint: &'static str) -> Self {
        GetInfoMetaData {
            msg: String::new(),
            display_url: false,
            display_source: false,
            display_socket_addr: false,
            retries: 0,
            url: format!("http://{}{server_info_endpoint}", meta.socket_addr()),
            meta,
        }
    }

    #[inline]
    pub(crate) fn set_err_msg(mut self, msg: String) -> Self {
        self.msg = msg;
        self
    }

    set_flag!(with_url, display_url, true);
    set_flag!(with_socket_addr, display_socket_addr, true);
    set_flag!(with_source, display_source, true);
    set_flag!(
        /// `GetInfoErr` default display is without addr
        without_url, display_url, false
    );
    set_flag!(
        /// `GetInfoErr` default display is without ip
        without_socket_addr, display_socket_addr, false
    );
    set_flag!(
        /// `GetInfoErr` default display is without source
        without_source, display_source, false
    );
}

impl Display for GetInfoMetaData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)?;
        if self.display_url {
            write!(f, ", with addr: {}", self.url)?;
        }
        if self.display_socket_addr {
            write!(f, ", with ip: {}", self.meta.socket_addr())?;
        }
        if self.display_source {
            write!(f, ", with source: {}", self.meta)?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct UnresponsiveCounter {
    pub(crate) hmw: usize,
    pub(crate) hmw_cached: usize,
    pub(crate) iw4: usize,
    pub(crate) iw4_cached: usize,
    pub(crate) used_cached_servers: usize,
}

impl UnresponsiveCounter {
    #[inline]
    pub(crate) fn total(&self) -> usize {
        self.hmw + self.hmw_cached + self.iw4 + self.iw4_cached
    }

    fn add(&mut self, from: &Sourced) {
        match from {
            Sourced::Hmw(_) => self.hmw += 1,
            Sourced::HmwCached(_) => self.hmw_cached += 1,
            Sourced::Iw4(_) => self.iw4 += 1,
            Sourced::Iw4Cached(_) => self.iw4_cached += 1,
        }
    }

    fn used_cached_server(&mut self) {
        self.used_cached_servers += 1
    }
}

pub(crate) enum Request {
    New(Sourced),
    Retry(GetInfoMetaData),
}

pub(crate) async fn try_get_info(
    from: Request,
    client: Client,
    server_info_endpoint: &'static str,
) -> Result<Server, GetInfoMetaData> {
    let meta_data = match from {
        Request::New(meta) => GetInfoMetaData::new(meta, server_info_endpoint),
        Request::Retry(mut err) => {
            err.retries += 1;
            err
        }
    };

    let server_response = match client.get(&meta_data.url).send().await {
        Ok(res) => res,
        Err(err) => return Err(meta_data.set_err_msg(err.without_url().to_string())),
    };

    if server_response.status() != STATUS_OK {
        return Err(meta_data.set_err_msg(format!("getInfo {}", server_response.status())));
    }

    match server_response.json::<GetInfo>().await {
        Ok(info) => Ok(Server {
            source: meta_data.meta,
            info,
        }),
        Err(err) => Err(meta_data.set_err_msg(err.without_url().to_string())),
    }
}

#[derive(Debug)]
pub(crate) struct HostMeta {
    pub(crate) resolved_addr: SocketAddr,
    pub(crate) server: ServerInfo,
}

impl HostMeta {
    fn from_ip(ip: IpAddr, server: ServerInfo) -> Self {
        Self {
            resolved_addr: SocketAddr::new(ip, server.port),
            server,
        }
    }

    fn try_from(host_ip: &str, webfront_url: &str, server: ServerInfo) -> Option<Self> {
        if let Some(set_resolved) = server
            .resolved_ip
            .as_deref()
            .and_then(|ip_str| ip_str.parse::<IpAddr>().ok())
        {
            trace!("used resolved from iw4: {set_resolved}");
            return Some(Self::from_ip(set_resolved, server));
        }

        resolve_address(&server.ip, host_ip, webfront_url)
            .map_err(|err| {
                error!(name: LOG_ONLY, "{err}, server_ip: {}, host_ip: {host_ip}, webfront_url: {webfront_url}", server.ip)
            })
            .map(|ip| Self::from_ip(ip, server))
            .ok()
    }
}

impl GetInfo {
    pub fn player_ct(&self) -> u8 {
        self.clients.checked_sub(self.bots).unwrap_or_else(|| {
            error!(name: LOG_ONLY, "Server: {}, found with invalid bot count. Bots: {} > Clients: {}",
                parse_hostname(&self.host_name),
                self.bots,
                self.clients
            );
            0
        })
    }

    pub(crate) fn max_public_slots(&self) -> u8 {
        self.max_clients
            .checked_sub(self.private_clients.max(0) as u8).unwrap_or_else(|| {
            error!(name: LOG_ONLY, "Server: {}, found with invalid private_client count. Private clients: {} > Clients: {}",
                parse_hostname(&self.host_name),
                self.private_clients,
                self.clients
            );
            0
        })
    }
}

#[derive(Debug)]
pub enum Sourced {
    Hmw(SocketAddr),
    HmwCached(SocketAddr),

    // Only pub so we can write tests for ensuring proper table formatting, `HostMeta` does not
    // need to be included, as it eventually gets converted to `Server` before it is displayed.
    #[expect(private_interfaces)]
    Iw4(HostMeta),

    Iw4Cached(SocketAddr),
}

impl Sourced {
    fn addr_copy(&self) -> Self {
        match self {
            &Sourced::Hmw(addr) => Sourced::Hmw(addr),
            &Sourced::HmwCached(addr) => Sourced::HmwCached(addr),
            &Sourced::Iw4Cached(addr) => Sourced::Iw4Cached(addr),
            Sourced::Iw4(host_meta) => Sourced::Iw4(HostMeta {
                resolved_addr: host_meta.resolved_addr,
                server: ServerInfo::default(),
            }),
        }
    }

    fn try_parse_hmw_master(ip_port: String) -> Option<Self> {
        macro_rules! hmw_fmt_err {
            ($($arg:tt)*) => {
                error!(name: LOG_ONLY, "Unexpected {SOURCE_HMW} formatting: {}", format_args!($($arg)*))
            }
        }

        match ip_port
            .rsplit_once(':')
            .map(|(ip, port)| (ip.parse().map_err(|err| (err, ip)), port.parse::<u16>()))
        {
            Some((Ok(ip), Ok(port))) => return Some(Self::Hmw(SocketAddr::new(ip, port))),
            Some((Err((err, ip_str)), Ok(port))) => {
                if let Some(ip) = try_resolve_from_str(ip_str) {
                    return Some(Self::Hmw(SocketAddr::new(ip, port)));
                }
                hmw_fmt_err!("failed to parse ip address in: {ip_port}, {err}")
            }
            Some((Ok(_), Err(err))) => {
                hmw_fmt_err!("failed to parse port in: {ip_port}, {err}")
            }
            Some((Err(_), Err(_))) => {
                hmw_fmt_err!("invalid string: {ip_port}")
            }
            None => {
                hmw_fmt_err!("address was not formatted with a port: {ip_port}")
            }
        }
        None
    }
}

pub(crate) trait Addressable {
    fn socket_addr(&self) -> SocketAddr;
}

impl Addressable for Sourced {
    fn socket_addr(&self) -> SocketAddr {
        match self {
            Sourced::Hmw(addr) | Sourced::HmwCached(addr) | Sourced::Iw4Cached(addr) => *addr,
            Sourced::Iw4(meta) => meta.resolved_addr,
        }
    }
}

impl Addressable for Server {
    fn socket_addr(&self) -> SocketAddr {
        self.source.socket_addr()
    }
}

impl Source {
    fn with_cached_ip(self, addr: SocketAddr) -> Sourced {
        match self {
            Source::Iw4Master => Sourced::Iw4Cached(addr),
            Source::HmwMaster => Sourced::HmwCached(addr),
        }
    }
}

pub(super) type LocationApiResponse = Vec<IpLocation>;
pub(super) type LocationBatchRes<'a> = (Vec<(&'a [IpAddr], LocationApiResponse)>, usize);

/// This API request is rate limited, see: [`Location`] for set limits. Returns the aligned data and the number of
/// `IpAddr`s that were included in the batched API requests. The return type is what [`process_region_requests`] expects.
///
/// [`process_region_requests`]: ops::process_region_requests
#[instrument(level = "trace", skip_all)]
pub(crate) async fn try_batched_location_lookup<'a>(
    ips: &'a [IpAddr],
    client: &Client,
) -> LocationBatchRes<'a> {
    const BATCH_CAP: usize = 100;
    thread_local! {
        static LOCATION_API_LIMITER: Cell<RateLimiter<Location>> = const { Cell::new(RateLimiter::<Location>::new()) };
    }

    async fn location_requests(
        batch: String,
        client: Client,
    ) -> Result<LocationApiResponse, ResponseErr> {
        let api_response = client
            .post(BATCH_LOCATION_URL)
            .body(batch)
            .send()
            .await
            .map_err(|err| ResponseErr::reqwest(LOCATION_SERVICE_PROVIDER, err))?;

        if api_response.status() != STATUS_OK {
            return Err(ResponseErr::bad_status("IP api", api_response));
        }

        serde_deserialize(api_response).await
    }

    let mut requests = Vec::with_capacity(ips.len().div_ceil(BATCH_CAP));
    let mut ips_requested = 0;
    let mut limiter = LOCATION_API_LIMITER.get();

    for batch in ips.chunks(BATCH_CAP) {
        if !limiter.within_limit() {
            break;
        }

        ips_requested += batch.len();
        requests.push(tokio::spawn(location_requests(
            serde_json::to_string(batch).expect("`[IpAddr]` is always fine to serialize"),
            client.clone(),
        )));
    }

    let mut responses = Vec::with_capacity(requests.len());
    for (request, batch) in requests.into_iter().zip(ips.chunks(BATCH_CAP)) {
        match request.await {
            Ok(Ok(data)) => {
                if batch.len() == data.len() {
                    responses.push((batch, data));
                } else {
                    error!(
                        "Location API returned unexpected data, discarded data for: {}",
                        DisplayCountOf(batch.len(), "hoster", "hosters")
                    );
                    error!(name: LOG_ONLY, "requested data for: {} ips, got data for: {} ips", batch.len(), data.len());
                }
            }
            Ok(Err(err)) => err.log_only(),
            Err(err) => error!(name: LOG_ONLY, "`location_requests` panicked! {err:?}"),
        }
    }

    if limiter.limited() {
        println!("{CLEAR_LINE}{RED}{limiter}{RESET}")
    }

    LOCATION_API_LIMITER.set(limiter);
    (responses, ips_requested)
}

#[instrument(level = "trace", skip_all)]
fn resolve_address(
    server_ip: &str,
    host_ip: &str,
    webfront_url: &str,
) -> Result<IpAddr, AddrParseError> {
    let ip_trim = server_ip.trim_matches('/').trim_matches(':');
    if !ip_trim.is_empty() && ip_trim != LOCAL_HOST {
        if let Ok(ip) = ip_trim.parse::<IpAddr>() {
            if !ip.is_loopback() && !ip.is_unspecified() {
                return Ok(ip);
            }
        } else if let Some(ip) = try_resolve_from_str(ip_trim) {
            return Ok(ip);
        }
    }

    parse_possible_ipv6(host_ip, webfront_url)
}

fn try_resolve_from_str(ip_str: &str) -> Option<IpAddr> {
    if ip_str.is_empty() {
        return None;
    }

    main_thread_state::Cache::with_borrow_mut(|cache| {
        if let Some(&attempt) = cache.dns_resolution.get(ip_str) {
            return attempt;
        }

        let resolved = (ip_str, 80)
            .to_socket_addrs()
            .ok()
            .and_then(|mut socket_addr| socket_addr.next().map(|socket| socket.ip()));

        cache.dns_resolution.insert(ip_str.to_string(), resolved);

        #[cfg(debug_assertions)]
        if let Some(ip) = resolved {
            trace!("Cached socket address of: {ip}, from: {ip_str}");
        }

        resolved
    })
}

#[instrument(level = "trace", skip_all)]
fn parse_possible_ipv6(ip: &str, webfront_url: &str) -> Result<IpAddr, AddrParseError> {
    fn parse_ipv6_webfront(webfront_url: &str) -> Option<&str> {
        const HTTP_ENDING: &str = "//";

        let ip_start = webfront_url
            .find(HTTP_ENDING)
            .map(|i| i + HTTP_ENDING.len())?;
        let ipv6_slice = if let Some(ip_end) = webfront_url.rfind(':') {
            if ip_end <= ip_start {
                error!(name: LOG_ONLY, "Bad ipv6 slice op: {webfront_url}");
                return None;
            }
            &webfront_url[ip_start..ip_end]
        } else {
            &webfront_url[ip_start..]
        };

        trace!("Parsed: {ipv6_slice}, from webfront_url");
        Some(ipv6_slice)
    }

    let ip_trim = ip.trim_matches('/').trim_matches(':');

    if let Some(ip) = try_resolve_from_str(ip_trim) {
        return Ok(ip);
    }

    match ip_trim.parse::<IpAddr>() {
        success @ Ok(_) => success,
        Err(err) => {
            let Some(ipv6_str) = parse_ipv6_webfront(webfront_url) else {
                return Err(err);
            };

            trace!("Failed to parse: {ip_trim} - {err}");
            ipv6_str.parse::<IpAddr>()
        }
    }
}
