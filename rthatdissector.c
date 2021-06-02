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
static int hf_rth_dsa_pdu_type = -1;
static gint ett_rth_dsa = -1;

static int
dissect_rth_dsa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    //proto_tree_add_protocol_format(tree, proto_rth_dsa, tvb, 14, 24, "RealtimeHAT DSA tag", plugin_version);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RealtimeHAT DSA tag");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_rth_dsa, tvb, 14, 24, ENC_NA);
    return tvb_captured_length(tvb);
}

static void
proto_register_rth_dsa(void)
{
	static hf_register_info hf[] = {
        { &hf_rth_dsa_pdu_type,
            { "FOO PDU Type", "foo.type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_rth_dsa
    };
    proto_rth_dsa = proto_register_protocol("Wireshark RealtimeHAT Plugin", "RealtimeHAT WS", "realtimehat_ws");
    proto_register_field_array(proto_rth_dsa, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void
proto_reg_handoff_rth_dsa(void)
{


    
    handle_rth_dsa = create_dissector_handle(dissect_rth_dsa, proto_rth_dsa);
    dissector_add_uint("eth.type", 0x813e, handle_rth_dsa);
    register_postdissector(handle_rth_dsa);
}

void
plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_rth_dsa;
    plug.register_handoff = proto_reg_handoff_rth_dsa; /* or NULL */
    proto_register_plugin(&plug);
}
