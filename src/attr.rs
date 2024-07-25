// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_string, parse_u16, parse_u32, parse_u64, parse_u8},
    DecodeError, Emitable, Parseable,
};

use crate::{
    Nl80211ChannelWidth, Nl80211InterfaceType, Nl80211StationInfo,
    Nl80211TransmitQueueStat, Nl80211WiPhyChannelType,
};

const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
const NL80211_ATTR_GENERATION: u16 = 46;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_4ADDR: u16 = 83;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
const NL80211_ATTR_WDEV: u16 = 153;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_CENTER_FREQ2: u16 = 161;
const NL80211_ATTR_TXQ_STATS: u16 = 265;
const NL80211_ATTR_WIPHY_FREQ_OFFSET: u16 = 290;
const NL80211_ATTR_MLO_LINKS: u16 = 312;
const NL80211_ATTR_MLO_LINK_ID: u16 = 313;

const ETH_ALEN: usize = 6;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211Attr {
    Wiphy(u32),
    WiphyName(String),
    IfIndex(u32),
    IfName(String),
    IfType(Nl80211InterfaceType),
    Mac([u8; ETH_ALEN]),
    Wdev(u64),
    Generation(u32),
    Use4Addr(bool),
    WiphyFreq(u32),
    WiphyFreqOffset(u32),
    WiphyChannelType(Nl80211WiphyChannelType),
    ChannelWidth(Nl80211ChannelWidth),
    CenterFreq1(u32),
    CenterFreq2(u32),
    WiphyTxPowerLevel(u32),
    Ssid(String),
    StationInfo(Vec<Nl80211StationInfo>),
    TransmitQueueStats(Vec<Nl80211TransmitQueueStat>),
    MloLinks(Vec<Nl80211MloLink>),
    WiphyRetryShort(u8),
    WiphyRetryLong(u8),
    WiphyFragThreshold(u32),
    WiphyRtsThreshold(u32),
    WiphyCoverageClass(u8),
    MaxNumScanSsids(u8),
    MaxNumSchedScanSsids(u8),
    MaxScanIeLen(u16),
    MaxSchedScanIeLen(u16),
    MaxMatchSets(u8),
    SupportIbssRsn(bool),
    SupportMeshAuth(bool),
    SupportApUapsd(bool),
    RoamSupport(bool),
    TdlsSupport(bool),
    TdlsExternalSetup(bool),
    CipherSuites(Vec<Nl80211CipherSuit>),
    MaxNumPmkids(u8),
    ControlPortEthertype(bool),
    WiphyAntennaAvailTx(u32),
    WiphyAntennaAvailRx(u32),
    ApProbeRespOffload(u32),
    WiphyAntennaTx(u32),
    WiphyAntennaRx(u32),
    SupportedIftypes(Vec<Nl80211IfMode>),
    WiphyBands(Vec<Nl80211Band>),
    Other(DefaultNla),
}

impl Nla for Nl80211Attr {
    fn value_len(&self) -> usize {
        match self {
            Self::IfIndex(_)
            | Self::Wiphy(_)
            | Self::IfType(_)
            | Self::Generation(_)
            | Self::WiphyFreq(_)
            | Self::WiphyFreqOffset(_)
            | Self::WiphyChannelType(_)
            | Self::CenterFreq1(_)
            | Self::CenterFreq2(_)
            | Self::WiphyTxPowerLevel(_)
            | Self::ChannelWidth(_)
            | Self::WiphyFragThreshold(_)
            | Self::WiphyRtsThreshold(_)
            | Self::WiphyAntennaAvailTx(_)
            | Self::WiphyAntennaAvailRx(_)
            | Self::ApProbeRespOffload(_)
            | Self::WiphyAntennaTx(_)
            | Self::WiphyAntennaRx(_) => 4,
            Self::Wdev(_) => 8,
            Self::IfName(ref s)
            | Self::Ssid(ref s)
            | Self::WiphyName(ref s) => s.len() + 1,
            Self::Mac(_) => ETH_ALEN,
            Self::Use4Addr(_) => 1,
            Self::WiphyRetryShort(_)
            | Self::WiphyRetryLong(_)
            | Self::WiphyCoverageClass(_)
            | Self::MaxNumScanSsids(_)
            | Self::MaxNumSchedScanSsids(_)
            | Self::MaxMatchSets(_)
            | Self::MaxNumPmkids(_) => 1,
            Self::TransmitQueueStats(ref nlas) => nlas.as_slice().buffer_len(),
            Self::StationInfo(ref nlas) => nlas.as_slice().buffer_len(),
            Self::MloLinks(ref links) => links.as_slice().buffer_len(),
            Self::MaxScanIeLen(_) | Self::MaxSchedScanIeLen(_) => 2,
            Self::SupportIbssRsn(_)
            | Self::SupportMeshAuth(_)
            | Self::SupportApUapsd(_)
            | Self::RoamSupport(_)
            | Self::TdlsSupport(_)
            | Self::TdlsExternalSetup(_)
            | Self::ControlPortEthertype(_) => 0,
            Self::CipherSuites(ref s) => 4 * s.len(),
            Self::SupportedIftypes(ref s) => s.as_slice().buffer_len(),
            Self::WiphyBands(ref s) => s.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Wiphy(_) => NL80211_ATTR_WIPHY,
            Self::WiphyName(_) => NL80211_ATTR_WIPHY_NAME,
            Self::IfIndex(_) => NL80211_ATTR_IFINDEX,
            Self::IfName(_) => NL80211_ATTR_IFNAME,
            Self::IfType(_) => NL80211_ATTR_IFTYPE,
            Self::Mac(_) => NL80211_ATTR_MAC,
            Self::Wdev(_) => NL80211_ATTR_WDEV,
            Self::Generation(_) => NL80211_ATTR_GENERATION,
            Self::Use4Addr(_) => NL80211_ATTR_4ADDR,
            Self::WiphyFreq(_) => NL80211_ATTR_WIPHY_FREQ,
            Self::WiphyFreqOffset(_) => NL80211_ATTR_WIPHY_FREQ_OFFSET,
            Self::WiphyChannelType(_) => NL80211_ATTR_WIPHY_CHANNEL_TYPE,
            Self::ChannelWidth(_) => NL80211_ATTR_CHANNEL_WIDTH,
            Self::CenterFreq1(_) => NL80211_ATTR_CENTER_FREQ1,
            Self::CenterFreq2(_) => NL80211_ATTR_CENTER_FREQ2,
            Self::WiphyTxPowerLevel(_) => NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
            Self::Ssid(_) => NL80211_ATTR_SSID,
            Self::StationInfo(_) => NL80211_ATTR_STA_INFO,
            Self::TransmitQueueStats(_) => NL80211_ATTR_TXQ_STATS,
            Self::MloLinks(_) => NL80211_ATTR_MLO_LINKS,
            Self::WiphyRetryShort(_) => NL80211_ATTR_WIPHY_RETRY_SHORT,
            Self::WiphyRetryLong(_) => NL80211_ATTR_WIPHY_RETRY_LONG,
            Self::WiphyFragThreshold(_) => NL80211_ATTR_WIPHY_FRAG_THRESHOLD,
            Self::WiphyRtsThreshold(_) => NL80211_ATTR_WIPHY_RTS_THRESHOLD,
            Self::WiphyCoverageClass(_) => NL80211_ATTR_WIPHY_COVERAGE_CLASS,
            Self::MaxNumScanSsids(_) => NL80211_ATTR_MAX_NUM_SCAN_SSIDS,
            Self::MaxNumSchedScanSsids(_) => {
                NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS
            }
            Self::MaxScanIeLen(_) => NL80211_ATTR_MAX_SCAN_IE_LEN,
            Self::MaxSchedScanIeLen(_) => NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN,
            Self::MaxMatchSets(_) => NL80211_ATTR_MAX_MATCH_SETS,
            Self::SupportIbssRsn(_) => NL80211_ATTR_SUPPORT_IBSS_RSN,
            Self::SupportMeshAuth(_) => NL80211_ATTR_SUPPORT_MESH_AUTH,
            Self::SupportApUapsd(_) => NL80211_ATTR_SUPPORT_AP_UAPSD,
            Self::RoamSupport(_) => NL80211_ATTR_ROAM_SUPPORT,
            Self::TdlsSupport(_) => NL80211_ATTR_TDLS_SUPPORT,
            Self::TdlsExternalSetup(_) => NL80211_ATTR_TDLS_EXTERNAL_SETUP,
            Self::CipherSuites(_) => NL80211_ATTR_CIPHER_SUITES,
            Self::MaxNumPmkids(_) => NL80211_ATTR_MAX_NUM_PMKIDS,
            Self::ControlPortEthertype(_) => {
                NL80211_ATTR_CONTROL_PORT_ETHERTYPE
            }
            Self::WiphyAntennaAvailTx(_) => NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX,
            Self::WiphyAntennaAvailRx(_) => NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX,
            Self::ApProbeRespOffload(_) => NL80211_ATTR_PROBE_RESP_OFFLOAD,
            Self::WiphyAntennaTx(_) => NL80211_ATTR_WIPHY_ANTENNA_TX,
            Self::WiphyAntennaRx(_) => NL80211_ATTR_WIPHY_ANTENNA_RX,
            Self::SupportedIftypes(_) => NL80211_ATTR_SUPPORTED_IFTYPES,
            Self::WiphyBands(_) => NL80211_ATTR_WIPHY_BANDS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::IfIndex(d)
            | Self::Wiphy(d)
            | Self::Generation(d)
            | Self::WiphyFreq(d)
            | Self::WiphyFreqOffset(d)
            | Self::CenterFreq1(d)
            | Self::CenterFreq2(d)
            | Self::WiphyTxPowerLevel(d)
            | Self::WiphyFragThreshold(d)
            | Self::WiphyRtsThreshold(d)
            | Self::WiphyAntennaAvailTx(d)
            | Self::WiphyAntennaAvailRx(d)
            | Self::ApProbeRespOffload(d)
            | Self::WiphyAntennaTx(d)
            | Self::WiphyAntennaRx(d) => NativeEndian::write_u32(buffer, *d),
            Self::MaxScanIeLen(d) | Self::MaxSchedScanIeLen(d) => {
                NativeEndian::write_u16(buffer, *d)
            }
            Self::Wdev(d) => NativeEndian::write_u64(buffer, *d),
            Self::IfType(d) => NativeEndian::write_u32(buffer, (*d).into()),
            Self::Mac(ref s) => buffer.copy_from_slice(s),
            Self::IfName(ref s)
            | Self::Ssid(ref s)
            | Self::WiphyName(ref s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Self::Use4Addr(_)
            | Self::SupportIbssRsn(_)
            | Self::SupportMeshAuth(_)
            | Self::SupportApUapsd(_)
            | Self::RoamSupport(_)
            | Self::TdlsSupport(_)
            | Self::TdlsExternalSetup(_)
            | Self::ControlPortEthertype(_) => (),
            Self::WiphyChannelType(d) => {
                NativeEndian::write_u32(buffer, (*d).into())
            }
            Self::ChannelWidth(d) => {
                NativeEndian::write_u32(buffer, (*d).into())
            }
            Self::StationInfo(ref nlas) => nlas.as_slice().emit(buffer),
            Self::TransmitQueueStats(ref nlas) => nlas.as_slice().emit(buffer),
            Self::MloLinks(ref links) => links.as_slice().emit(buffer),
            Self::WiphyRetryShort(d)
            | Self::WiphyRetryLong(d)
            | Self::WiphyCoverageClass(d)
            | Self::MaxNumScanSsids(d)
            | Self::MaxNumSchedScanSsids(d)
            | Self::MaxMatchSets(d)
            | Self::MaxNumPmkids(d) => buffer[0] = *d,
            Self::CipherSuites(ref suits) => {
                let nums: Vec<u32> =
                    suits.as_slice().iter().map(|s| u32::from(*s)).collect();
                for (i, v) in nums.as_slice().iter().enumerate() {
                    buffer[i * 4..(i + 1) * 4]
                        .copy_from_slice(&v.to_ne_bytes());
                }
            }
            Self::SupportedIftypes(ref s) => s.as_slice().emit(buffer),
            Self::WiphyBands(ref s) => s.as_slice().emit(buffer),

            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nl80211Attr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_ATTR_IFINDEX => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_IFINDEX value {:?}", payload);
                Self::IfIndex(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_WIPHY value {:?}", payload);
                Self::Wiphy(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_NAME => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_NAME value {:?}",
                    payload
                );
                Self::WiphyName(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_IFNAME => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_IFNAME value {:?}", payload);
                Self::IfName(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_IFTYPE => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_IFTYPE value {:?}", payload);
                Self::IfType(parse_u32(payload).context(err_msg)?.into())
            }
            NL80211_ATTR_WDEV => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_WDEV value {:?}", payload);
                Self::Wdev(parse_u64(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAC => Self::Mac(if payload.len() == ETH_ALEN {
                let mut ret = [0u8; ETH_ALEN];
                ret.copy_from_slice(&payload[..ETH_ALEN]);
                ret
            } else {
                return Err(format!(
                    "Invalid length of NL80211_ATTR_MAC, expected length {} got {:?}",
                    ETH_ALEN, payload
                )
                .into());
            }),
            NL80211_ATTR_GENERATION => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_GENERATION value {:?}",
                    payload
                );
                Self::Generation(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_4ADDR => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_4ADDR value {:?}", payload);
                Self::Use4Addr(parse_u8(payload).context(err_msg)? > 0)
            }
            NL80211_ATTR_WIPHY_FREQ => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FREQ value {:?}",
                    payload
                );
                Self::WiphyFreq(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_FREQ_OFFSET => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FREQ_OFFSET value {:?}",
                    payload
                );
                Self::WiphyFreqOffset(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_CHANNEL_TYPE => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_CHANNEL_TYPE value {:?}",
                    payload
                );
                Self::WiphyChannelType(
                    parse_u32(payload).context(err_msg)?.into(),
                )
            }
            NL80211_ATTR_CHANNEL_WIDTH => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CHANNEL_WIDTH value {:?}",
                    payload
                );
                Self::ChannelWidth(parse_u32(payload).context(err_msg)?.into())
            }
            NL80211_ATTR_CENTER_FREQ1 => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CENTER_FREQ1 value {:?}",
                    payload
                );
                Self::CenterFreq1(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_CENTER_FREQ2 => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CENTER_FREQ2 value {:?}",
                    payload
                );
                Self::CenterFreq2(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_TX_POWER_LEVEL => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_TX_POWER_LEVEL value {:?}",
                    payload
                );
                Self::WiphyTxPowerLevel(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_SSID => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_SSID value {:?}", payload);
                Self::Ssid(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_STA_INFO => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_STA_INFO value {:?}",
                    payload
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211StationInfo::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::StationInfo(nlas)
            }
            NL80211_ATTR_TXQ_STATS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_TXQ_STATS value {:?}",
                    payload
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211TransmitQueueStat::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::TransmitQueueStats(nlas)
            }
            NL80211_ATTR_MLO_LINKS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MLO_LINKS value {:?}",
                    payload
                );
                let mut links = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    links.push(
                        Nl80211MloLink::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::MloLinks(links)
            }
            NL80211_ATTR_WIPHY_RETRY_SHORT => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RETRY_SHORT value {:?}",
                    payload
                );
                Self::WiphyRetryShort(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_RETRY_LONG => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RETRY_LONG value {:?}",
                    payload
                );
                Self::WiphyRetryLong(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_FRAG_THRESHOLD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FRAG_THRESHOLD value {:?}",
                    payload
                );
                Self::WiphyFragThreshold(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_RTS_THRESHOLD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RTS_THRESHOLD value {:?}",
                    payload
                );
                Self::WiphyRtsThreshold(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_COVERAGE_CLASS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_COVERAGE_CLASS value {:?}",
                    payload
                );
                Self::WiphyCoverageClass(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_NUM_SCAN_SSIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_NUM_SCAN_SSIDS value {:?}",
                    payload
                );
                Self::MaxNumScanSsids(
                    parse_u8(payload).context(err_msg)?.into(),
                )
            }
            NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS value {:?}",
                    payload
                );
                Self::MaxNumSchedScanSsids(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_SCAN_IE_LEN => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_SCAN_IE_LEN value {:?}",
                    payload
                );
                Self::MaxScanIeLen(parse_u16(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN value {:?}",
                    payload
                );
                Self::MaxSchedScanIeLen(parse_u16(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_MATCH_SETS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_MATCH_SETS value {:?}",
                    payload
                );
                Self::MaxMatchSets(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_SUPPORT_IBSS_RSN => Self::SupportIbssRsn(true),
            NL80211_ATTR_SUPPORT_MESH_AUTH => Self::SupportMeshAuth(true),
            NL80211_ATTR_SUPPORT_AP_UAPSD => Self::SupportApUapsd(true),
            NL80211_ATTR_ROAM_SUPPORT => Self::RoamSupport(true),
            NL80211_ATTR_TDLS_SUPPORT => Self::TdlsSupport(true),
            NL80211_ATTR_TDLS_EXTERNAL_SETUP => Self::TdlsExternalSetup(true),
            NL80211_ATTR_CIPHER_SUITES => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CIPHER_SUITES value {:?}",
                    payload
                );
                let mut suits = Vec::new();
                for i in 0..(payload.len() / 4) {
                    suits.push(
                        parse_u32(&payload[i * 4..(i + 1) * 4])
                            .context(err_msg.clone())?
                            .into(),
                    );
                }
                Self::CipherSuites(suits)
            }
            NL80211_ATTR_MAX_NUM_PMKIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_NUM_PMKIDS value {:?}",
                    payload
                );
                Self::MaxNumPmkids(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_CONTROL_PORT_ETHERTYPE => {
                Self::ControlPortEthertype(true)
            }
            NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX value {:?}",
                    payload
                );
                Self::WiphyAntennaAvailTx(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX value {:?}",
                    payload
                );
                Self::WiphyAntennaAvailRx(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_PROBE_RESP_OFFLOAD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_PROBE_RESP_OFFLOAD value {:?}",
                    payload
                );
                Self::ApProbeRespOffload(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_ANTENNA_TX => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_ANTENNA_TX value {:?}",
                    payload
                );
                Self::WiphyAntennaTx(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_ANTENNA_RX => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_ANTENNA_RX value {:?}",
                    payload
                );
                Self::WiphyAntennaRx(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_SUPPORTED_IFTYPES => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_SUPPORTED_IFTYPES value {:?}",
                    payload
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211IfMode::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::SupportedIftypes(nlas)
            }
            NL80211_ATTR_WIPHY_BANDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_BANDS value {:?}",
                    payload
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211Band::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::WiphyBands(nlas)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211MloLinkNla {
    Id(u8),
    Mac([u8; ETH_ALEN]),
    Other(DefaultNla),
}

impl Nla for Nl80211MloLinkNla {
    fn value_len(&self) -> usize {
        match self {
            Self::Id(_) => 1,
            Self::Mac(_) => ETH_ALEN,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Id(_) => NL80211_ATTR_MLO_LINK_ID,
            Self::Mac(_) => NL80211_ATTR_MAC,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Id(d) => buffer[0] = *d,
            Self::Mac(ref s) => buffer.copy_from_slice(s),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211MloLinkNla
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_ATTR_MLO_LINK_ID => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MLO_LINK_ID value {:?}",
                    payload
                );
                Self::Id(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAC => Self::Mac(if payload.len() == ETH_ALEN {
                let mut ret = [0u8; ETH_ALEN];
                ret.copy_from_slice(&payload[..ETH_ALEN]);
                ret
            } else {
                return Err(format!(
                    "Invalid length of NL80211_ATTR_MAC, expected length {} got {:?}",
                    ETH_ALEN, payload
                )
                .into());
            }),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Nl80211MloLink {
    pub id: u8,
    pub mac: [u8; ETH_ALEN],
}

impl Nla for Nl80211MloLink {
    fn value_len(&self) -> usize {
        Vec::<Nl80211MloLinkNla>::from(self).as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.id as u16 + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        Vec::<Nl80211MloLinkNla>::from(self).as_slice().emit(buffer)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211MloLink
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Self::default();
        let payload = buf.value();
        let err_msg =
            format!("Invalid NL80211_ATTR_MLO_LINKS value {:?}", payload);
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            match Nl80211MloLinkNla::parse(nla).context(err_msg.clone())? {
                Nl80211MloLinkNla::Id(d) => ret.id = d,
                Nl80211MloLinkNla::Mac(s) => ret.mac = s,
                Nl80211MloLinkNla::Other(attr) => {
                    log::warn!(
                        "Got unsupported NL80211_ATTR_MLO_LINKS value {:?}",
                        attr
                    )
                }
            }
        }
        Ok(ret)
    }
}

impl From<&Nl80211MloLink> for Vec<Nl80211MloLinkNla> {
    fn from(link: &Nl80211MloLink) -> Self {
        vec![
            Nl80211MloLinkNla::Id(link.id),
            Nl80211MloLinkNla::Mac(link.mac),
        ]
    }
}
