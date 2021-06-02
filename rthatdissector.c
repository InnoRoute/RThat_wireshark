/* rthatdissector.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
 // ulbricht@innoroute.de 2021

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define WS_BUILD_DLL

#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_attributes.h>
#include <ws_symbol_export.h>
#include <ws_version.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);


static int proto_rth_dsa = -1;
static dissector_handle_t handle_rth_dsa;
static int hf_rth_dsa_inport = -1;
static int hf_rth_dsa_outport = -1;
static int hf_rth_dsa_ttiq = -1;
static int hf_rth_dsa_badrsn = -1;
static int hf_rth_dsa_bad = -1;
static int hf_rth_dsa_delaypkt =-1;
static int hf_rth_dsa_bridgets=-1;
static int hf_rth_dsa_rxts=-1;
static int hf_rth_dsa_txts=-1;
static dissector_handle_t ethertype_handle;
static int hf_rth_dsa_txconfid=-1;
static int hf_rth_dsa_ctlts=-1;
static int hf_rth_dsa_pad=-1;
static gint ett_rth_dsa = -1;
static int hf_rth_dsa_ethtype=-1;
static gint ett_vlan = -1;
static int hf_rth_dsa_trailer = -1;

static int
dissect_rth_dsa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
gint offset = 0;
volatile guint16 encap_proto;
proto_tree *volatile vlan_tree;

    //proto_tree_add_protocol_format(tree, proto_rth_dsa, tvb, 14, 24, "RealtimeHAT DSA tag", plugin_version);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RealtimeHAT DSA tag");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_rth_dsa, tvb, 0, 24, ENC_NA);
    proto_tree *rth_dsa_tree = proto_item_add_subtree(ti, ett_rth_dsa);
//    proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_inport, tvb, offset, 1, ENC_BIG_ENDIAN);
//    
    proto_tree_add_bits_item(rth_dsa_tree,hf_rth_dsa_inport,tvb,offset*8+0,5,ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(rth_dsa_tree,hf_rth_dsa_outport,tvb,offset*8+5,5,ENC_BIG_ENDIAN);
		if(tvb_get_ntohs(tvb, 0) & 0b11111000 == 0b11111000){//out packet
			proto_tree_add_bits_item(rth_dsa_tree,hf_rth_dsa_ttiq,tvb,offset*8+10,5,ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(rth_dsa_tree,hf_rth_dsa_delaypkt,tvb,offset*8+15,1,ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_txts, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_txconfid, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
//			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
//			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
//			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}else{
			proto_tree_add_bits_item(rth_dsa_tree,hf_rth_dsa_badrsn,tvb,offset*8+10,5,ENC_BIG_ENDIAN);
			proto_tree_add_bits_item(rth_dsa_tree,hf_rth_dsa_bad,tvb,offset*8+15,1,ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_bridgets, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_rxts, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_ctlts, tvb, offset, 8, ENC_BIG_ENDIAN);
			offset += 8;
//			proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_pad, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		
		}
		proto_tree_add_item(rth_dsa_tree, hf_rth_dsa_ethtype, tvb, offset, 2, ENC_BIG_ENDIAN);
    //vlan_tree = NULL;
    //vlan_tree = proto_item_add_subtree(ti, ett_vlan);
    encap_proto = tvb_get_ntohs(tvb, offset);
   // printf("ethertype:%llx\n",encap_proto);
   // ethertype(encap_proto, tvb, 4, pinfo, tree, vlan_tree, hf_vlan_etype, hf_vlan_trailer, 0);
   
		 ethertype_data_t ethertype_data;
		 ethertype_data.etype = encap_proto;
		 ethertype_data.payload_offset = 24;
		 ethertype_data.fh_tree = rth_dsa_tree;
		 ethertype_data.trailer_id = hf_rth_dsa_trailer;
		 ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
   
    return tvb_captured_length(tvb);
    //proto_register_ethertype();
}

static void
proto_register_rth_dsa(void)
{
    	static hf_register_info hf[] = {
        { &hf_rth_dsa_inport,
            { "Input port", "rth_dsa.inport",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_outport,
            { "Output port", "rth_dsa.outport",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_ttiq,
            { "TTI Queue", "rth_dsa.ttiq",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_badrsn,
            { "BAD reason", "rth_dsa.badrsn",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_bad,
            { "BAD", "rth_dsa.bad",
            FT_BOOLEAN, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_delaypkt,
            { "Delay pkt", "rth_dsa.delaypkt",
            FT_BOOLEAN, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_bridgets,
            { "Bridge timestamp", "rth_dsa.bridgets",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_rxts,
            { "RX timestamp", "rth_dsa.rxts",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_ctlts,
            { "CTL timestamp", "rth_dsa.ctlts",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_pad,
            { "padding", "rth_dsa.pad",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_rth_dsa_ethtype,
            { "next Ethertype", "rth_dsa.ethtype",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_txts,
            { "TX timestamp", "rth_dsa.txts",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
       { &hf_rth_dsa_txconfid,
            { "TX confirmation ID", "rth_dsa.txconfid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rth_dsa_trailer,
            { "Trailer", "rth_dsa.trailer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_rth_dsa
    };
    proto_rth_dsa = proto_register_protocol("RealtimeHAT DSA tag", "RealtimeHAT WS", "realtimehat_ws");
    proto_register_field_array(proto_rth_dsa, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void
proto_reg_handoff_rth_dsa(void)
{



    

    handle_rth_dsa = create_dissector_handle(dissect_rth_dsa, proto_rth_dsa);
    dissector_add_uint("ethertype", 0x813e, handle_rth_dsa);
    ethertype_handle = find_dissector_add_dependency("ethertype", proto_rth_dsa);
    //register_postdissector(handle_rth_dsa);
}

void
plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_rth_dsa;
    plug.register_handoff = proto_reg_handoff_rth_dsa; /* or NULL */
    proto_register_plugin(&plug);
}
