/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DECODE_EVENTS_H__
#define __DECODE_EVENTS_H__

enum {
    /* LORAWAN EVENTS */
    LORAWAN_PKT_TOO_SMALL,
    LORAWAN_FRAME_HEADER_TOO_BIG,
    LORAWAN_FRAME_PKT_INVALID,
    LORAWAN_FRAME_PKT_INVALID,
    LORAWAN_FRAME_CONTROL_INVALID,

    /* IPV4 EVENTS */
    IPV4_PKT_TOO_SMALL = 1,         /**< ipv4 pkt smaller than minimum header size */
    IPV4_HLEN_TOO_SMALL,            /**< ipv4 header smaller than minimum size */
    IPV4_IPLEN_SMALLER_THAN_HLEN,   /**< ipv4 pkt len smaller than ip header size */
    IPV4_TRUNC_PKT,                 /**< truncated ipv4 packet */

    /* IPV4 OPTIONS */
    IPV4_OPT_INVALID,               /**< invalid ip options */
    IPV4_OPT_INVALID_LEN,           /**< ip options with invalid len */
    IPV4_OPT_MALFORMED,             /**< malformed ip options */
    IPV4_OPT_PAD_REQUIRED,          /**< pad bytes are needed in ip options */
    IPV4_OPT_EOL_REQUIRED,          /**< "end of list" needed in ip options */
    IPV4_OPT_DUPLICATE,             /**< duplicated ip option */
    IPV4_OPT_UNKNOWN,               /**< unknown ip option */
    IPV4_WRONG_IP_VER,              /**< wrong ip version in ip options */

    /* IPV6 EVENTS */
    IPV6_PKT_TOO_SMALL,             /**< ipv6 packet smaller than minimum size */
    IPV6_TRUNC_PKT,                 /**< truncated ipv6 packet */
    IPV6_TRUNC_EXTHDR,              /**< truncated ipv6 extension header */
    IPV6_EXTHDR_DUPL_FH,            /**< duplicated "fragment" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_RH,            /**< duplicated "routing" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_HH,            /**< duplicated "hop-by-hop" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_DH,            /**< duplicated "destination" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_AH,            /**< duplicated "authentication" header in ipv6 extension headers */
    IPV6_EXTHDR_DUPL_EH,            /**< duplicated "ESP" header in ipv6 extension headers */

    IPV6_EXTHDR_INVALID_OPTLEN,     /**< the opt len in an hop or dst hdr is invalid. */
    IPV6_WRONG_IP_VER,              /**< wrong version in ipv6 */


    /* UDP EVENTS */
    UDP_PKT_TOO_SMALL,              /**< udp packet smaller than minimum size */
    UDP_HLEN_TOO_SMALL,             /**< udp header smaller than minimum size */
    UDP_HLEN_INVALID,               /**< invalid len of upd header */


    /* ETHERNET EVENTS */
    ETHERNET_PKT_TOO_SMALL,         /**< ethernet packet smaller than minimum size */

     /* RAW EVENTS */
    IPRAW_INVALID_IPV,              /**< invalid ip version in ip raw */


    /* should always be last! */
    DECODE_EVENT_MAX,
};

#endif /* __DECODE_EVENTS_H__ */

