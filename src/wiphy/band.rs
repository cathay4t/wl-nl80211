// SPDX-License-Identifier: MIT

// Most documentation comments are copied and modified from linux kernel
// include/uapi/linux/nl80211.h which is holding these license disclaimer:
/*
 * 802.11 netlink interface public header
 *
 * Copyright 2006-2010 Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2008 Michael Wu <flamingice@sourmilk.net>
 * Copyright 2008 Luis Carlos Cobo <luisca@cozybit.com>
 * Copyright 2008 Michael Buesch <m@bues.ch>
 * Copyright 2008, 2009 Luis R. Rodriguez <lrodriguez@atheros.com>
 * Copyright 2008 Jouni Malinen <jouni.malinen@atheros.com>
 * Copyright 2008 Colin McCabe <colin@cozybit.com>
 * Copyright 2015-2017	Intel Deutschland GmbH
 * Copyright (C) 2018-2024 Intel Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_u16, parse_u32},
    DecodeError, Emitable, Parseable,
};

use crate::Nl80211Error;

const NL80211_BAND_ATTR_FREQS: u16 = 1;
const NL80211_BAND_ATTR_RATES: u16 = 2;
const NL80211_BAND_ATTR_HT_MCS_SET: u16 = 3;
const NL80211_BAND_ATTR_HT_CAPA: u16 = 4;
const NL80211_BAND_ATTR_HT_AMPDU_FACTOR: u16 = 5;
const NL80211_BAND_ATTR_HT_AMPDU_DENSITY: u16 = 6;
const NL80211_BAND_ATTR_VHT_MCS_SET: u16 = 7;
const NL80211_BAND_ATTR_VHT_CAPA: u16 = 8;
const NL80211_BAND_ATTR_IFTYPE_DATA: u16 = 9;
const NL80211_BAND_ATTR_EDMG_CHANNELS: u16 = 10;
const NL80211_BAND_ATTR_EDMG_BW_CONFIG: u16 = 11;
// TODO: Kernel has no properly defined struct for 802.11ah sub-1G MCS and CAPA,
// postpone the deserialization.
// const NL80211_BAND_ATTR_S1G_MCS_NSS_SET: u16 = 12;
// const NL80211_BAND_ATTR_S1G_CAPA: u16 = 13;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211Band {
    /// Supported frequencies in this band.
    Freqs(Vec<Nl80211Frequency>),
    /// Supported bitrates in this band.
    Rates(Vec<Nl80211Rate>),
    /// The MCS set as defined in 802.11n.
    HtMcsSet(Nl80211BandMcsInfo),
    /// HT capabilities, as in the HT information IE.
    HtCapa(Nl80211HtCaps),
    /// Maximum A-MPDU length factor, as in 11n.
    HtAmpduFactor(u8),
    /// Minimum A-MPDU spacing, as in 11n.
    HtAmpduDensity(u8),
    /// The MCS set as defined in 802.11ac.
    VhtMcsSet(Nl80211BandVhtMcsInfo),
    /// VHT capabilities, as in the HT information IE
    VhtCapa(Nl80211VhtCaps),
    /// Interface type data
    IftypeData(Vec<Nl80211BandIftypeData>),
    /// Bitmap that indicates the 2.16 GHz channel(s) that are allowed to be
    /// used for EDMG transmissions. Defined by IEEE P802.11ay/D4.0 section
    /// 9.4.2.251.
    EdmgChannels(u8),
    /// Channel BW Configuration subfield encodes the allowed channel bandwidth
    /// configurations.
    EdmgBwConfig(u8),

    Other(DefaultNla),
}

impl Nla for Nl80211Band {
    fn value_len(&self) -> usize {
        match self {
            Self::Freqs(ref s) => s.as_slice().buffer_len(),
            Self::Rates(ref s) => s.as_slice().buffer_len(),
            Self::HtMcsSet(s) => s.len(),
            Self::HtCapa(_) => 2,
            Self::HtAmpduFactor(_) => 1,
            Self::HtAmpduDensity(_) => 1,
            Self::VhtMcsSet(s) => s.len(),
            Self::VhtCapa() => 4,
            Self::IftypeData(ref s) => s.as_slice().buffer_len(),
            Self::EdmgChannels(_) => 1,
            Self::EdmgBwConfig(_) => 1,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Freqs(_) => NL80211_BAND_ATTR_FREQS,
            Self::Rates(_) => NL80211_BAND_ATTR_RATES,
            Self::HtMcsSet(_) => NL80211_BAND_ATTR_HT_MCS_SET,
            Self::HtCapa(_) => NL80211_BAND_ATTR_HT_CAPA,
            Self::HtAmpduFactor(_) => NL80211_BAND_ATTR_HT_AMPDU_FACTOR,
            Self::HtAmpduDensity(_) => NL80211_BAND_ATTR_HT_AMPDU_DENSITY,
            Self::VhtMcsSet(_) => NL80211_BAND_ATTR_VHT_MCS_SET,
            Self::VhtCapa() => NL80211_BAND_ATTR_VHT_CAPA,
            Self::IftypeData(_) => NL80211_BAND_ATTR_IFTYPE_DATA,
            Self::EdmgChannels(_) => NL80211_BAND_ATTR_EDMG_CHANNELS,
            Self::EdmgBwConfig(_) => NL80211_BAND_ATTR_EDMG_BW_CONFIG,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, _buffer: &mut [u8]) {
        match self {
            Self::Freqs(ref d) => d.as_slice().emit(buffer),
            Self::Rates(ref d) => d.as_slice().emit(buffer),
            Self::HtMcsSet(d) => d.emit_value(buffer),
            Self::HtCapa(d) => buffer.copy_from_slice(d.bits()),
            Self::HtAmpduFactor(d) => buffer[0] = *d,
            Self::HtAmpduDensity(d) => buffer[0] = *d,
            Self::VhtMcsSet(d) => d.emit_dalue(buffer),
            Self::VhtCapa(d) => buffer.copy_from_slice(d.bits()),
            Self::IftypeData(ref d) => d.as_slice().emit(buffer),
            Self::EdmgChannels(d) => buffer[0] = *d,
            Self::EdmgBwConfig(d) => buffer[0] = *d,
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nl80211Band {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_BAND_ATTR_FREQS => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_FREQS value {:?}",
                    payload
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211Frequency::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::Freqs(nlas)
            }
            NL80211_BAND_ATTR_RATES => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_RATES value {:?}",
                    payload
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211Rates::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::Rates(nlas)
            }
            NL80211_BAND_ATTR_HT_MCS_SET => {
                Self::HtMcsSet(Nl80211BandMcsInfo::try_from(payload)?)
            }
            NL80211_BAND_ATTR_HT_CAPA => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_HT_CAPA value {:?}",
                    payload
                );
                Self::HtCapa(Nl80211HtCaps::from_bits_retain(
                    parse_u16(payload).context(err_msg)?,
                ))
            }
            NL80211_BAND_ATTR_HT_AMPDU_FACTOR => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_HT_AMPDU_FACTOR value {:?}",
                    payload
                );
                Self::HtAmpduFactor(parse_u8(payload).context(err_msg)?)
            }
            NL80211_BAND_ATTR_HT_AMPDU_DENSITY => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_HT_AMPDU_DENSITY value {:?}",
                    payload
                );
                Self::HtAmpduDensity(parse_u8(payload).context(err_msg)?)
            }
            NL80211_BAND_ATTR_VHT_MCS_SET => {
                Self::VhtMcsSet(Nl80211BandMcsInfo::try_from(payload)?)
            }
            NL80211_BAND_ATTR_VHT_CAPA => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_HT_CAPA value {:?}",
                    payload
                );
                Self::VhtCapa(Nl80211VhtCaps::from_bits_retain(
                    parse_u32(payload).context(err_msg)?,
                ))
            }
            NL80211_BAND_ATTR_IFTYPE_DATA => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_IFTYPE_DATA value {:?}",
                    payload
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211BandIftypeData::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::IftypeData(nlas)
            }
            NL80211_BAND_ATTR_EDMG_CHANNELS => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_EDMG_CHANNELS value {:?}",
                    payload
                );
                Self::EdmgChannels(parse_u8(payload).context(err_msg)?)
            }
            NL80211_BAND_ATTR_EDMG_BW_CONFIG => {
                let err_msg = format!(
                    "Invalid NL80211_BAND_ATTR_EDMG_BW_CONFIG value {:?}",
                    payload
                );
                Self::EdmgBwConfig(parse_u8(payload).context(err_msg)?)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const IEEE80211_HT_MCS_MASK_LEN: usize = 10;
const NL80211_BAND_MCS_INFO_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211BandMcsInfo {
    pub rx_mask: [u8; IEEE80211_HT_MCS_MASK_LEN],
    pub rx_highest: u16,
    pub tx_params: u8,
}

impl Nl80211BandMcsInfo {
    pub fn len(&self) -> usize {
        // `struct ieee80211_mcs_info`.
        // Kernel document confirmed this is 16 bytes
        NL80211_BAND_MCS_INFO_LEN
    }

    pub fn emit_value(&self, buffer: &mut [u8]) {
        if buffer.len() < NL80211_BAND_MCS_INFO_LEN {
            log::error!(
                "Buffer size is smaller than NL80211_BAND_MCS_INFO_LEN \
                {NL80211_BAND_MCS_INFO_LEN}"
            );
            return;
        }
        buffer.iter_mut().for_each(|m| *m = 0);
        buffer[..IEEE80211_HT_MCS_MASK_LEN].copy_from_slice(&self.rx_mask);
        LittleEndian::write_u16(
            buffer[IEEE80211_HT_MCS_MASK_LEN..IEEE80211_HT_MCS_MASK_LEN + 2],
            self.rx_highest,
        );
        buffer[IEEE80211_HT_MCS_MASK_LEN + 2] = self.tx_params;
    }
}

impl TryFrom<&[u8]> for Nl80211BandMcsInfo {
    fn try_from(payload: &[u8]) -> Result<Self, Nl80211Error> {
        if payload.len() < NL80211_BAND_MCS_INFO_LEN {
            return Err(Nl80211Error::DecodeFailed(
                format!(
                    "Expecting `struct ieee80211_ht_mcs_info` u8 array with \
                    size {NL80211_BAND_MCS_INFO_LEN}, but got length {}",
                    payload.len()
                )
                .into(),
            ));
        }

        Ok(Self {
            rx_mask: payload[..IEEE80211_HT_MCS_MASK_LEN].clone(),
            rx_highest: LittleEndian::read_u16(
                payload
                    [IEEE80211_HT_MCS_MASK_LEN..IEEE80211_HT_MCS_MASK_LEN + 2],
            ),
            tx_params: payload[IEEE80211_HT_MCS_MASK_LEN + 2],
        })
    }
}

const NL80211_BAND_VHT_MCS_INFO_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Nl80211BandVhtMcsInfo {
    pub rx_mcs_map: u16,
    pub rx_highest: u16,
    pub tx_mcs_map: u16,
    pub tx_highest: u16,
}

impl Nl80211BandVhtMcsInfo {
    pub fn len(&self) -> usize {
        // `struct ieee80211_vht_mcs_info`
        // Kernel document confirmed this is 32 bytes
        Nl80211_BAND_VHT_MCS_INFO_LEN
    }

    pub fn emit_value(&self, buffer: &mut [u8]) {
        if buffer.len() < NL80211_BAND_VHT_MCS_INFO_LEN {
            log::error!(
                "Buffer size is smaller than NL80211_BAND_VHT_MCS_INFO_LEN \
                {NL80211_BAND_VHT_MCS_INFO_LEN}"
            );
            return;
        }
        buffer.iter_mut().for_each(|m| *m = 0);
        LittleEndian::write_u16(buffer[0..2], self.rx_mcs_map);
        LittleEndian::write_u16(buffer[2..4], self.rx_highest);
        LittleEndian::write_u16(buffer[4..6], self.tx_mcs_map);
        LittleEndian::write_u16(buffer[6..8], self.tx_highest);
    }
}

impl TryFrom<&[u8]> for Nl80211BandVhtMcsInfo {
    fn try_from(payload: &[u8]) -> Result<Self, Nl80211Error> {
        if payload.len() < NL80211_BAND_VHT_MCS_INFO_LEN {
            return Err(Nl80211Error::DecodeFailed(
                format!(
                    "Expecting `struct ieee80211_vht_mcs_info` u8 array with \
                    size {NL80211_BAND_VHT_MCS_INFO_LEN}, but got length {}",
                    payload.len()
                )
                .into(),
            ));
        }

        Ok(Self {
            rx_mcs_map: LittleEndian::read_u16(payload[0..2]),
            rx_highest: LittleEndian::read_u16(payload[2..4]),
            tx_mcs_map: LittleEndian::read_u16(payload[4..6]),
            tx_highest: LittleEndian::read_u16(payload[6..8]),
        })
    }
}

const IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895: u32 = 0x00000000;
const IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991: u32 = 0x00000001;
const IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454: u32 = 0x00000002;
const IEEE80211_VHT_CAP_MAX_MPDU_MASK: u32 = 0x00000003;
const IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ: u32 = 0x00000004;
const IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ: u32 = 0x00000008;
const IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK: u32 = 0x0000000C;
const IEEE80211_VHT_CAP_RXLDPC: u32 = 0x00000010;
const IEEE80211_VHT_CAP_SHORT_GI_80: u32 = 0x00000020;
const IEEE80211_VHT_CAP_SHORT_GI_160: u32 = 0x00000040;
const IEEE80211_VHT_CAP_TXSTBC: u32 = 0x00000080;
const IEEE80211_VHT_CAP_RXSTBC_1: u32 = 0x00000100;
const IEEE80211_VHT_CAP_RXSTBC_2: u32 = 0x00000200;
const IEEE80211_VHT_CAP_RXSTBC_3: u32 = 0x00000300;
const IEEE80211_VHT_CAP_RXSTBC_4: u32 = 0x00000400;
const IEEE80211_VHT_CAP_RXSTBC_MASK: u32 = 0x00000700;
const IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE: u32 = 0x00000800;
const IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE: u32 = 0x00001000;
const IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT: u32 = 13;
const IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK: u32 =
    (7 << IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT);
const IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT: u32 = 16;
const IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK: u32 =
    (7 << IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT);
const IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE: u32 = 0x00080000;
const IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE: u32 = 0x00100000;
const IEEE80211_VHT_CAP_VHT_TXOP_PS: u32 = 0x00200000;
const IEEE80211_VHT_CAP_HTC_VHT: u32 = 0x00400000;
const IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT: u32 = 23;
const IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK: u32 =
    (7 << IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT);
const IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_UNSOL_MFB: u32 = 0x08000000;
const IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB: u32 = 0x0c000000;
const IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN: u32 = 0x10000000;
const IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN: u32 = 0x20000000;
const IEEE80211_VHT_CAP_EXT_NSS_BW_MASK: u32 = 0xc0000000;

bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211VhtCaps: u32 {
        const MaxMpduLength3895 = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895;
        const MaxMpduLength7991 = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991;
        const MaxMpduLength11454 = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454;
        const MaxMpduMask = IEEE80211_VHT_CAP_MAX_MPDU_MASK;
        const SuppChanWidth160mhz = IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
        const SuppChanWidth160With80plus80mhz =
            IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
        const SuppChanWidthMask = IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK;
        const Rxldpc = IEEE80211_VHT_CAP_RXLDPC;
        const ShortGi80 = IEEE80211_VHT_CAP_SHORT_GI_80;
        const ShortGi160 = IEEE80211_VHT_CAP_SHORT_GI_160;
        const TxStbc = IEEE80211_VHT_CAP_TXSTBC;
        const Rxstbc1 = IEEE80211_VHT_CAP_RXSTBC_1;
        const Rxstbc2 = IEEE80211_VHT_CAP_RXSTBC_2;
        const Rxstbc3 = IEEE80211_VHT_CAP_RXSTBC_3;
        const Rxstbc4 = IEEE80211_VHT_CAP_RXSTBC_4;
        const RxstbcMask = IEEE80211_VHT_CAP_RXSTBC_MASK;
        const SuBeamformerCapable = IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE;
        const SuBeamformeeCapable = IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE;
        const BeamformeeStsMask = IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK;
        const SoundingDimensionsMask = IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;
        const MuBeamformerCapable = IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE;
        const MuBeamformeeCapable = IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE;
        const VhtTxopPs = IEEE80211_VHT_CAP_VHT_TXOP_PS;
        const HtcVht = IEEE80211_VHT_CAP_HTC_VHT;
        const MaxAMpduLengthExponentMask =
            IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
        const VhtLinkAdaptationVhtUnsolMfb =
            IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_UNSOL_MFB;
        const VhtLinkAdaptationVhtMrqMfb =
            IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB;
        const RxAntennaPattern = IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN;
        const TxAntennaPattern = IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN;
        const ExtNssBwMask = IEEE80211_VHT_CAP_EXT_NSS_BW_MASK;
        const _ = !0;
    }
}

const NL80211_BAND_IFTYPE_ATTR_IFTYPES: u16 = 1;
const NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC: u16 = 2;
const NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY: u16 = 3;
const NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET: u16 = 4;
const NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE: u16 = 5;
const NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA: u16 = 6;
const NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS: u16 = 7;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC: u16 = 8;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY: u16 = 9;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET: u16 = 10;
const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE: u16 = 11;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211BandIftypeData {
    IfTypes(Vec<Nl80211IfType>),
    HeCapMac([u8; 6]),
    HeCapPhy([u8; 11]),
    /**
     * struct ieee80211_he_mcs_nss_supp - HE Tx/Rx HE MCS NSS Support Field
     *
     * This structure holds the data required for the Tx/Rx HE MCS NSS Support Field
     * described in P802.11ax_D2.0 section 9.4.2.237.4
     *
     * @rx_mcs_80: Rx MCS map 2 bits for each stream, total 8 streams, for channel
     *     widths less than 80MHz.
     * @tx_mcs_80: Tx MCS map 2 bits for each stream, total 8 streams, for channel
     *     widths less than 80MHz.
     * @rx_mcs_160: Rx MCS map 2 bits for each stream, total 8 streams, for channel
     *     width 160MHz.
     * @tx_mcs_160: Tx MCS map 2 bits for each stream, total 8 streams, for channel
     *     width 160MHz.
     * @rx_mcs_80p80: Rx MCS map 2 bits for each stream, total 8 streams, for
     *     channel width 80p80MHz.
     * @tx_mcs_80p80: Tx MCS map 2 bits for each stream, total 8 streams, for
     *     channel width 80p80MHz.
    struct ieee80211_he_mcs_nss_supp {
        __le16 rx_mcs_80;
        __le16 tx_mcs_80;
        __le16 rx_mcs_160;
        __le16 tx_mcs_160;
        __le16 rx_mcs_80p80;
        __le16 tx_mcs_80p80;
    } __packed;
     */
    HeCapMcsSet([u8; 12]),
    HeCapPpe([u8; 25]),
    He6ghzCapa(Vec<Ieee80211He6ghzCapa>),
    VendorElems(Vec<u8>),
    EhtCapMac([u8; 2]),
    EhtCapPhy([u8; 9]),
    // TODO, variable length union in C `struct ieee80211_eht_mcs_nss_supp`.
    EhtCapMcsSet(Vec<u8>),
    EhtCapPpe([u8; 32]),
    Other(DefaultNla),
}

impl Nla for Nl80211BandIftypeData {
    fn value_len(&self) -> usize {
        match self {
            Self::IfTypes(ref s) => _Nl80211IfTypeVec::from(s).value_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::IfTypes(_) => NL80211_BAND_IFTYPE_ATTR_IFTYPES,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::IfTypes(ref d) => {
                _Nl80211IfTypeVec::from(d).as_slice().emit(buffer)
            }
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211BandIftypeData
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_BAND_IFTYPE_ATTR_IFTYPES => Self::IfTypes(
                _Nl80211IfTypeVec::parse(buf)
                    .context(
                        "Invalid NLA for NL80211_BAND_IFTYPE_ATTR_IFTYPES",
                    )?
                    .into(),
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

const NL80211_IFTYPE_ADHOC: u16 = 1;
const NL80211_IFTYPE_STATION: u16 = 2;
const NL80211_IFTYPE_AP: u16 = 3;
const NL80211_IFTYPE_AP_VLAN: u16 = 4;
const NL80211_IFTYPE_WDS: u16 = 5;
const NL80211_IFTYPE_MONITOR: u16 = 6;
const NL80211_IFTYPE_MESH_POINT: u16 = 7;
const NL80211_IFTYPE_P2P_CLIENT: u16 = 8;
const NL80211_IFTYPE_P2P_GO: u16 = 9;
const NL80211_IFTYPE_P2P_DEVICE: u16 = 10;
const NL80211_IFTYPE_OCB: u16 = 11;
const NL80211_IFTYPE_NAN: u16 = 12;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211IfType {
    Adhoc,
    Station,
    Ap,
    ApVlan,
    Wds,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    Ocb,
    Nan,
    Other(u16),
}

impl From<u16> for Nl80211IfType {
    fn from(d: u16) -> Self {
        match d {
            NL80211_IFTYPE_ADHOC => Self::Adhoc,
            NL80211_IFTYPE_STATION => Self::Station,
            NL80211_IFTYPE_AP => Self::Ap,
            NL80211_IFTYPE_AP_VLAN => Self::ApVlan,
            NL80211_IFTYPE_WDS => Self::Wds,
            NL80211_IFTYPE_MONITOR => Self::Monitor,
            NL80211_IFTYPE_MESH_POINT => Self::MeshPoint,
            NL80211_IFTYPE_P2P_CLIENT => Self::PopClient,
            NL80211_IFTYPE_P2P_GO => Self::PopGo,
            NL80211_IFTYPE_P2P_DEVICE => Self::PopDevice,
            NL80211_IFTYPE_OCB => Self::Ocb,
            NL80211_IFTYPE_NAN => Self::Nan,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211IfType> for u16 {
    fn from(v: Nl80211IfType) -> Self {
        match v {
            Nl80211IfType::Adhoc => NL80211_IFTYPE_ADHOC,
            Nl80211IfType::Station => NL80211_IFTYPE_STATION,
            Nl80211IfType::Ap => NL80211_IFTYPE_AP,
            Nl80211IfType::ApVlan => NL80211_IFTYPE_AP_VLAN,
            Nl80211IfType::Wds => NL80211_IFTYPE_WDS,
            Nl80211IfType::Monitor => NL80211_IFTYPE_MONITOR,
            Nl80211IfType::MeshPoint => NL80211_IFTYPE_MESH_POINT,
            Nl80211IfType::PopClient => NL80211_IFTYPE_P2P_CLIENT,
            Nl80211IfType::PopGo => NL80211_IFTYPE_P2P_GO,
            Nl80211IfType::PopDevice => NL80211_IFTYPE_P2P_DEVICE,
            Nl80211IfType::Ocb => NL80211_IFTYPE_OCB,
            Nl80211IfType::Nan => NL80211_IFTYPE_NAN,
            Nl80211IfType::Other(d) => d,
        }
    }
}

// The kernel function `nl80211_put_iftypes()` is using mode number as NLA kind
struct _Nl80211IfTypeVec(Vec<Nl80211IfType>);

impl Deref for _Nl80211IfTypeVec {
    type Target = Vec<Nl80211IfType>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Nla for Nl80211IfType {
    fn value_len(&self) -> usize {
        0
    }

    fn emit_value(&self, buffer: &mut [u8]) {}

    fn kind(&self) -> u16 {
        self.into()
    }
}

impl Nla for _Nl80211IfTypeVec {
    fn value_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer)
    }

    fn kind(&self) -> u16 {
        NL80211_BAND_IFTYPE_ATTR_IFTYPES
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for _Nl80211IfTypeVec
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let mut if_types: Vec<Nl80211IfType> = Vec::new();
        for nla in NlasIterator::new(payload) {
            let nla =
                &nla.context("invalid NL80211_BAND_IFTYPE_ATTR_IFTYPES value")?;
            if_types.push(nla.kind().into());
        }
        Ok(Self(if_types))
    }
}

/* HE 6 GHz band capabilities */
const IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START: u16 = 0x0007;
const IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP: u16 = 0x0038;
const IEEE80211_HE_6GHZ_CAP_MAX_MPDU_LEN: u16 = 0x00c0;
const IEEE80211_HE_6GHZ_CAP_SM_PS: u16 = 0x0600;
const IEEE80211_HE_6GHZ_CAP_RD_RESPONDER: u16 = 0x0800;
const IEEE80211_HE_6GHZ_CAP_RX_ANTPAT_CONS: u16 = 0x1000;
const IEEE80211_HE_6GHZ_CAP_TX_ANTPAT_CONS: u16 = 0x2000;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Ieee80211He6ghzCapa {}

const NL80211_FREQUENCY_ATTR_FREQ: u16 = 1;
const NL80211_FREQUENCY_ATTR_DISABLED: u16 = 2;
const NL80211_FREQUENCY_ATTR_NO_IR: u16 = 3;
// const __NL80211_FREQUENCY_ATTR_NO_IBSS: u16 = 4;
const NL80211_FREQUENCY_ATTR_RADAR: u16 = 5;
const NL80211_FREQUENCY_ATTR_MAX_TX_POWER: u16 = 6;
const NL80211_FREQUENCY_ATTR_DFS_STATE: u16 = 7;
const NL80211_FREQUENCY_ATTR_DFS_TIME: u16 = 8;
const NL80211_FREQUENCY_ATTR_NO_HT40_MINUS: u16 = 9;
const NL80211_FREQUENCY_ATTR_NO_HT40_PLUS: u16 = 10;
const NL80211_FREQUENCY_ATTR_NO_80MHZ: u16 = 11;
const NL80211_FREQUENCY_ATTR_NO_160MHZ: u16 = 12;
const NL80211_FREQUENCY_ATTR_DFS_CAC_TIME: u16 = 13;
const NL80211_FREQUENCY_ATTR_INDOOR_ONLY: u16 = 14;
const NL80211_FREQUENCY_ATTR_IR_CONCURRENT: u16 = 15;
const NL80211_FREQUENCY_ATTR_NO_20MHZ: u16 = 16;
const NL80211_FREQUENCY_ATTR_NO_10MHZ: u16 = 17;
const NL80211_FREQUENCY_ATTR_WMM: u16 = 18;
const NL80211_FREQUENCY_ATTR_NO_HE: u16 = 19;
const NL80211_FREQUENCY_ATTR_OFFSET: u16 = 20;
const NL80211_FREQUENCY_ATTR_1MHZ: u16 = 21;
const NL80211_FREQUENCY_ATTR_2MHZ: u16 = 22;
const NL80211_FREQUENCY_ATTR_4MHZ: u16 = 23;
const NL80211_FREQUENCY_ATTR_8MHZ: u16 = 24;
const NL80211_FREQUENCY_ATTR_16MHZ: u16 = 25;
const NL80211_FREQUENCY_ATTR_NO_320MHZ: u16 = 26;
const NL80211_FREQUENCY_ATTR_NO_EHT: u16 = 27;
const NL80211_FREQUENCY_ATTR_PSD: u16 = 28;
const NL80211_FREQUENCY_ATTR_DFS_CONCURRENT: u16 = 29;
const NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT: u16 = 30;
const NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT: u16 = 31;
const NL80211_FREQUENCY_ATTR_CAN_MONITOR: u16 = 32;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211Frequency {
    /// Frequency in MHz
    Freq(u32),
    /// Channel is disabled in current regulatory domain
    Disabled,
    /// no mechanisms that initiate radiation are permitted on this channel,
    /// this includes sending probe requests, or modes of operation that
    /// require beaconing.
    NoIr,
    /// Radar detection is mandatory on this channel in current regulatory
    /// domain.
    Radar,
    /// Maximum transmission power in mBm (100 * dBm)
    MaxTxPower(u32),
    /// current state for DFS
    DfsState(Nl80211DfsState),
    /// time in milliseconds for how long this channel is in this DFS state
    DfsTime(u32),
    /// HT40- isn't possible with this channel as the control channel
    NoHt40Minus,
    /// HT40+ isn't possible with this channel as the control channel
    NoHt40Plus,
    ///  any 80 MHz channel using this channel as the primary or any of the
    ///  secondary channels isn't possible, this includes 80+80 channels
    No80Mhz,
    /// any 160 MHz (but not 80+80) channel using this channel as the primary
    /// or any of the secondary channels isn't possible
    No160Mhz,
    /// DFS CAC time in milliseconds.
    DfsCacTime(u32),
    /// Only indoor use is permitted on this channel. A channel that has the
    /// INDOOR_ONLY attribute can only be used when there is a clear assessment
    /// that the device is operating in an indoor surroundings, i.e., it is
    /// connected to AC power (and not through portable DC inverters) or is
    /// under the control of a master that is acting as an AP and is connected
    /// to AC power.
    IndoorOnly,
    /// IR operation is allowed on this channel if it's connected concurrently
    /// to a BSS on the same channel on the 2 GHz band or to a channel in
    /// the same UNII band (on the 5 GHz band), and IEEE80211_CHAN_RADAR is
    /// not set. Instantiating a GO or TDLS off-channel on a channel that
    /// has the IR_CONCURRENT attribute set can be done when there is a
    /// clear assessment that the device is operating under the guidance of
    /// an authorized master, i.e., setting up a GO or TDLS off-channel
    /// while the device is also connected to an AP with DFS and radar
    /// detection on the UNII band (it is up to user-space, i.e.,
    /// wpa_supplicant to perform the required verifications). Using this
    /// attribute for IR is disallowed for master interfaces (IBSS, AP).
    IrConcurrent,
    /// 20 MHz operation is not allowed on this channel in current regulatory
    /// domain.
    No20Mhz,
    /// 10 MHz operation is not allowed on this channel in current regulatory
    /// domain.
    No10Mhz,
    /// this channel has wmm limitations.
    Wmm(Vec<Nl80211WmmRule>),
    /// HE operation is not allowed on this channel in current regulatory
    /// domain.
    NoHe,
    /// frequency offset in KHz
    Offset(u32),
    /// 1 MHz operation is allowed
    Allow1Mhz,
    /// 2 MHz operation is allowed
    Allow2Mhz,
    /// 4 MHz operation is allowed
    Allow4Mhz,
    /// 8 MHz operation is allowed
    Allow8Mhz,
    /// 16 MHz operation is allowed
    Allow16Mhz,
    /// any 320 MHz channel using this channel
    /// as the primary or any of the secondary channels isn't possible
    No320Mhz,
    /// EHT operation is not allowed on this channel in current regulatory
    /// domain.
    NoEht,
    /// Power spectral density (in dBm) that is allowed on this channel in
    /// current regulatory domain.
    Psd(i8),
    /// Operation on this channel is allowed for peer-to-peer or adhoc
    /// communication under the control of a DFS master which operates on the
    /// same channel (FCC-594280 D01 Section B.3). Should be used together with
    /// `NL80211_RRF_DFS` only.
    DfsConcurrent,
    /// Client connection to VLP AP not allowed using this channel
    No6GhzVlpClient,
    /// Client connection to AFC AP not allowed using this channel
    No6GhzAfcclient,
    /// This channel can be used in monitor mode despite other (regulatory)
    /// restrictions, even if the channel is otherwise completely disabled.
    CanMonitor,
    /// Place holder for new attribute of `NL80211_BAND_ATTR_FREQS`
    Other(DefaultNla),
}

impl Nla for Nl80211Frequency {
    fn value_len(&self) -> usize {
        todo!();
        match self {
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, _buffer: &mut [u8]) {
        match self {
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211Frequency
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

#[derive(debug, partialeq, eq, clone)]
pub struct Nl80211Rate {}

const IEEE80211_HT_CAP_LDPC_CODING: u16 = 0x0001;
const IEEE80211_HT_CAP_SUP_WIDTH_20_40: u16 = 0x0002;
const IEEE80211_HT_CAP_SM_PS: u16 = 0x000C;
const IEEE80211_HT_CAP_GRN_FLD: u16 = 0x0010;
const IEEE80211_HT_CAP_SGI_20: u16 = 0x0020;
const IEEE80211_HT_CAP_SGI_40: u16 = 0x0040;
const IEEE80211_HT_CAP_TX_STBC: u16 = 0x0080;
const IEEE80211_HT_CAP_RX_STBC: u16 = 0x0300;
const IEEE80211_HT_CAP_DELAY_BA: u16 = 0x0400;
const IEEE80211_HT_CAP_MAX_AMSDU: u16 = 0x0800;
const IEEE80211_HT_CAP_DSSSCCK40: u16 = 0x1000;
const IEEE80211_HT_CAP_40MHZ_INTOLERANT: u16 = 0x4000;
const IEEE80211_HT_CAP_LSIG_TXOP_PROT: u16 = 0x8000;

bitflags! {
    #[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
    #[non_exhaustive]
    pub struct Nl80211HtCaps: u16 {
        const LdpcCoding = IEEE80211_HT_CAP_LDPC_CODING;
        const SupWidth2040 = IEEE80211_HT_CAP_SUP_WIDTH_20_40;
        const SmPs = IEEE80211_HT_CAP_SM_PS;
        const GrnFld = IEEE80211_HT_CAP_GRN_FLD;
        const Sgi20 = IEEE80211_HT_CAP_SGI_20;
        const Sgi40 = IEEE80211_HT_CAP_SGI_40;
        const TxStbc = IEEE80211_HT_CAP_TX_STBC;
        const RxStbc = IEEE80211_HT_CAP_RX_STBC;
        const DelayBa = IEEE80211_HT_CAP_DELAY_BA;
        const MaxAmsdu = IEEE80211_HT_CAP_MAX_AMSDU;
        const Dssscck40 = IEEE80211_HT_CAP_DSSSCCK40;
        const Intolerant40Mhz = IEEE80211_HT_CAP_40MHZ_INTOLERANT;
        const LsigTxopProt = IEEE80211_HT_CAP_LSIG_TXOP_PROT;
        const _ = !0;
    }
}

const NL80211_DFS_USABLE: u32 = 0;
const NL80211_DFS_UNAVAILABLE: u32 = 1;
const NL80211_DFS_AVAILABLE: u32 = 2;

/// DFS states for channels
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211DfsState {
    /// The channel can be used, but channel availability check (CAC) must be
    /// performed before using it for AP or IBSS.
    Usable,
    /// A radar has been detected on this channel, it is therefore marked as
    /// not available.
    Unavailable,
    /// The channel has been CAC checked and is available.
    Available,
    /// Place holder for new state
    Other(u32),
}

impl From<u32> for Nl80211DfsState {
    fn from(d: u32) -> Self {
        match d {
            NL80211_DFS_USABLE => Self::Usable,
            NL80211_DFS_UNAVAILABLE => Self::Unavailable,
            NL80211_DFS_AVAILABLE => Self::Available,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211DfsState> for u32 {
    fn from(v: Nl80211DfsState) -> Self {
        match v {
            Nl80211DfsState::Usable => NL80211_DFS_USABLE,
            Nl80211DfsState::Unavailable => NL80211_DFS_UNAVAILABLE,
            Nl80211DfsState::Available => NL80211_DFS_AVAILABLE,
            Nl80211DfsState::Other(d) => d,
        }
    }
}

const NL80211_WMMR_CW_MIN: u16 = 1;
const NL80211_WMMR_CW_MAX: u16 = 2;
const NL80211_WMMR_AIFSN: u16 = 3;
const NL80211_WMMR_TXOP: u16 = 4;

/// DFS states for channels
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211WmmRule {
    /// Minimum contention window slot
    CwMin(u16),
    /// Maximum contention window slot
    CwMax(u16),
    /// Arbitration Inter Frame Space
    Aifsn(u8),
    /// Maximum allowed tx operation time
    Txop(u16),
    /// Place holder for new entry of `enum nl80211_wmm_rule`
    Other(DefaultNla),
}

impl Nla for Nl80211WmmRule {
    fn value_len(&self) -> usize {
        todo!();
        match self {
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, _buffer: &mut [u8]) {
        match self {
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211WmmRule
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
