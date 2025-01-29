#include "packet-d2gs.h"

#include <stdio.h>
#include <epan/packet.h>

#ifndef VERSION
#define VERSION "0.0.1"
#endif

void proto_register_d2gs(void);
void proto_reg_handoff_d2gs(void);

static dissector_handle_t d2gs_handle;

#define D2GS_PORT 4000
static range_t *tcp_port_range = (range_t*)"4000";

static int proto_d2gs;

static int hf_d2gs_type;
static int hf_createclientplayer_guid;
static int hf_createclientplayer_class;
static int hf_createclientplayer_name;
static int hf_createclientplayer_x;
static int hf_createclientplayer_y;

static int hf_stateadd_unit;
static int hf_stateadd_guid;
static int hf_stateadd_streamlen;
static int hf_stateadd_streambytes;

static int hf_pip_unit;
static int hf_pip_guid;

static int hf_baseskill_amt;
static int hf_baseskill_playerid;
static int hf_baseskill_skill;
static int hf_baseskill_skilllvl;

static int hf_updateitemskill_unk1;
static int hf_updateitemskill_guid;
static int hf_updateitemskill_skill;
static int hf_updateitemskill_amt;
static int hf_updateitemskill_unk2;

static int hf_updateitemoskill_unk1;
static int hf_updateitemoskill_guid;
static int hf_updateitemoskill_skill;
static int hf_updateitemoskill_baselevel;
static int hf_updateitemoskill_bonusamt;
static int hf_updateitemoskill_unk2;

static int hf_setskill_unit;
static int hf_setskill_guid;
static int hf_setskill_hand;
static int hf_setskill_skill;
static int hf_setskill_unk1;

static int hf_unknown13_array;

static int hf_questinfo_array;

static int hf_gamequestinfo_array;

static int hf_gamehandshake_unit;
static int hf_gamehandshake_guid;

static int hf_unknown14_array;

static int hf_setbyteattr_attr;
static int hf_setbyteattr_amt;

static int hf_setwordattr_attr;
static int hf_setwordattr_amt;

static int hf_itemactionworld_entity;
static int hf_itemactionworld_arraylen;
static int hf_itemactionworld_array;

static int hf_itemactionowned_unknown1;
static int hf_itemactionowned_arraylen;
static int hf_itemactionowned_array;

static int hf_lamu_fields;
static int hf_lamu_fields2;
static int hf_lamu_life;
static int hf_lamu_mana;
static int hf_lamu_stamina;
static int hf_lamu_x;
static int hf_lamu_y;
static int hf_lamu_unk;

static int * const lamu_fields[] = {
    &hf_lamu_life,
    &hf_lamu_mana,
    &hf_lamu_stamina,
};
static int * const lamu_fields2[] = {
    &hf_lamu_x,
    &hf_lamu_y,
    &hf_lamu_unk,
};

static int hf_loadact_act;
static int hf_loadact_drlg_seed;
static int hf_loadact_area;
static int hf_loadact_obj_seed;

static gint ett_d2gs;
static gint ett_cmd;
static gint ett_stream;
static gint ett_array;
static gint ett_skill;
static gint ett_lamu_fields;

static const value_string d2gs_stypes[] = {
    { D2GS_GAMELOADING, "D2GS_GAMELOADING" },
    { D2GS_GAMEFLAGS, "D2GS_GAMEFLAGS" },
    { D2GS_LOADSUCCESSFUL, "D2GS_LOADSUCCESSFUL" },
    { D2GS_LOADACT, "D2GS_LOADACT" },
    { D2GS_LOADCOMPLETE, "D2GS_LOADCOMPLETE" },
    { D2GS_UNLOADCOMPLETE, "D2GS_UNLOADCOMPLETE" },
    { D2GS_GAMEEXITSUCCESSFUL, "D2GS_GAMEEXITSUCCESSFUL" },
    { D2GS_MAPREVEAL, "D2GS_MAPREVEAL" },
    { D2GS_MAPHIDE, "D2GS_MAPHIDE" },
    { D2GS_ASSIGNLVLWARP, "D2GS_ASSIGNLVLWARP" },
    { D2GS_REMOVEOBJECT, "D2GS_REMOVEOBJECT" },
    { D2GS_GAMEHANDSHAKE, "D2GS_GAMEHANDSHAKE" },
    { D2GS_NPCHIT, "D2GS_NPCHIT" },
    { D2GS_PLAYERSTOP, "D2GS_PLAYERSTOP" },
    { D2GS_OBJECTSTATE, "D2GS_OBJECTSTATE" },
    { D2GS_PLAYERMOVE, "D2GS_PLAYERMOVE" },
    { D2GS_CHARTOOBJ, "D2GS_CHARTOOBJ" },
    { D2GS_REPORTKILL, "D2GS_REPORTKILL" },
    { D2GS_S_UNKNOWN1, "D2GS_S_UNKNOWN1" },
    { D2GS_S_UNKNOWN2, "D2GS_S_UNKNOWN2" },
    { D2GS_S_UNKNOWN3, "D2GS_S_UNKNOWN3" },
    { D2GS_REASSIGNPLAYER, "D2GS_REASSIGNPLAYER" },
    { D2GS_S_UNKNOWN4, "D2GS_S_UNKNOWN4" },
    { D2GS_UNUSED1, "D2GS_UNUSED1" },
    { D2GS_S_UNKNOWN5, "D2GS_S_UNKNOWN5" },
    { D2GS_SMALLGOLDPICKUP, "D2GS_SMALLGOLDPICKUP" },
    { D2GS_BADDEXP, "D2GS_BADDEXP" },
    { D2GS_WADDEXP, "D2GS_WADDEXP" },
    { D2GS_DWADDEXP, "D2GS_DWADDEXP" },
    { D2GS_SETBYTEATTR, "D2GS_SETBYTEATTR" },
    { D2GS_SETWORDATTR, "D2GS_SETWORDATTR" },
    { D2GS_SETDWORDATTR, "D2GS_SETDWORDATTR" },
    { D2GS_ATTRIBUTEUPDATE, "D2GS_ATTRIBUTEUPDATE" },
    { D2GS_UPDATEITEMOSKILL, "D2GS_UPDATEITEMOSKILL" },
    { D2GS_UPDATEITEMSKILL, "D2GS_UPDATEITEMSKILL" },
    { D2GS_SETSKILL, "D2GS_SETSKILL" },
    { D2GS_S_UNKNOWN6, "D2GS_S_UNKNOWN6" },
    { D2GS_S_UNKNOWN7, "D2GS_S_UNKNOWN7" },
    { D2GS_GAMECHAT, "D2GS_GAMECHAT" },
    { D2GS_NPCINFO, "D2GS_NPCINFO" },
    { D2GS_QUESTINFO, "D2GS_QUESTINFO" },
    { D2GS_GAMEQUESTINFO, "D2GS_GAMEQUESTINFO" },
    { D2GS_NPCTRANSACTION, "D2GS_NPCTRANSACTION" },
    { D2GS_UNUSED2, "D2GS_UNUSED2" },
    { D2GS_PLAYSOUND, "D2GS_PLAYSOUND" },
    { D2GS_UNUSED3, "D2GS_UNUSED3" },
    { D2GS_UNUSED4, "D2GS_UNUSED4" },
    { D2GS_UNUSED5, "D2GS_UNUSED5" },
    { D2GS_UNUSED6, "D2GS_UNUSED6" },
    { D2GS_UNUSED7, "D2GS_UNUSED7" },
    { D2GS_UNUSED8, "D2GS_UNUSED8" },
    { D2GS_UNUSED9, "D2GS_UNUSED9" },
    { D2GS_UNUSED10, "D2GS_UNUSED10" },
    { D2GS_UNUSED11, "D2GS_UNUSED11" },
    { D2GS_UNUSED12, "D2GS_UNUSED12" },
    { D2GS_UNUSED13, "D2GS_UNUSED13" },
    { D2GS_UNUSED14, "D2GS_UNUSED14" },
    { D2GS_UNUSED15, "D2GS_UNUSED15" },
    { D2GS_UNUSED16, "D2GS_UNUSED16" },
    { D2GS_UNUSED17, "D2GS_UNUSED17" },
    { D2GS_UNUSED18, "D2GS_UNUSED18" },
    { D2GS_UNUSED19, "D2GS_UNUSED19" },
    { D2GS_UPDATEITEMSTATS, "D2GS_UPDATEITEMSTATS" },
    { D2GS_USESTACKABLEITEM, "D2GS_USESTACKABLEITEM" },
    { D2GS_S_UNKNOWN8, "D2GS_S_UNKNOWN8" },
    { D2GS_UNUSED20, "D2GS_UNUSED20" },
    { D2GS_CLEARCURSOR, "D2GS_CLEARCURSOR" },
    { D2GS_UNUSED21, "D2GS_UNUSED21" },
    { D2GS_UNUSED22, "D2GS_UNUSED22" },
    { D2GS_S_UNKNOWN9, "D2GS_S_UNKNOWN9" },
    { D2GS_UNUSED23, "D2GS_UNUSED23" },
    { D2GS_RELATOR1, "D2GS_RELATOR1" },
    { D2GS_RELATOR2, "D2GS_RELATOR2" },
    { D2GS_UNUSED24, "D2GS_UNUSED24" },
    { D2GS_UNUSED25, "D2GS_UNUSED25" },
    { D2GS_UNUSED26, "D2GS_UNUSED26" },
    { D2GS_UNITSKILLONTARGET, "D2GS_UNITSKILLONTARGET" },
    { D2GS_UNITCASTSKILL, "D2GS_UNITCASTSKILL" },
    { D2GS_MERCFORHIRE, "D2GS_MERCFORHIRE" },
    { D2GS_STARTMERCLIST, "D2GS_STARTMERCLIST" },
    { D2GS_STARTGAME, "D2GS_STARTGAME" },
    { D2GS_WORLDOBJECT, "D2GS_WORLDOBJECT" },
    { D2GS_QUESTLOGINFO, "D2GS_QUESTLOGINFO" },
    { D2GS_PLAYERSLOTREFRESH, "D2GS_PLAYERSLOTREFRESH" },
    { D2GS_S_UNKNOWN10, "D2GS_S_UNKNOWN10" },
    { D2GS_S_UNKNOWN11, "D2GS_S_UNKNOWN11" },
    { D2GS_UNUSED27, "D2GS_UNUSED27" },
    { D2GS_UNUSED28, "D2GS_UNUSED28" },
    { D2GS_S_UNKNOWN12, "D2GS_S_UNKNOWN12" },
    { D2GS_CREATECLIENTPLAYER, "D2GS_CREATECLIENTPLAYER" },
    { D2GS_EVENTMESSAGES, "D2GS_EVENTMESSAGES" },
    { D2GS_PLAYERJOINED, "D2GS_PLAYERJOINED" },
    { D2GS_PLAYERLEFT, "D2GS_PLAYERLEFT" },
    { D2GS_QUESTITEMSTATE, "D2GS_QUESTITEMSTATE" },
    { D2GS_S_UNKNOWN13, "D2GS_S_UNKNOWN13" },
    { D2GS_S_UNKNOWN14, "D2GS_S_UNKNOWN14" },
    { D2GS_TOWNPORTALSTATE, "D2GS_TOWNPORTALSTATE" },
    { D2GS_S_UNKNOWN15, "D2GS_S_UNKNOWN15" },
    { D2GS_S_UNKNOWN16, "D2GS_S_UNKNOWN16" },
    { D2GS_WAYPOINTMENU, "D2GS_WAYPOINTMENU" },
    { D2GS_UNUSED29, "D2GS_UNUSED29" },
    { D2GS_PLAYERKILLCOUNT, "D2GS_PLAYERKILLCOUNT" },
    { D2GS_S_UNKNOWN17, "D2GS_S_UNKNOWN17" },
    { D2GS_NPCMOVE, "D2GS_NPCMOVE" },
    { D2GS_NPCMOVETOTARGET, "D2GS_NPCMOVETOTARGET" },
    { D2GS_NPCSTATE, "D2GS_NPCSTATE" },
    { D2GS_S_UNKNOWN18, "D2GS_S_UNKNOWN18" },
    { D2GS_NPCACTION, "D2GS_NPCACTION" },
    { D2GS_NPCATTACK, "D2GS_NPCATTACK" },
    { D2GS_NPCSTOP, "D2GS_NPCSTOP" },
    { D2GS_S_UNKNOWN19, "D2GS_S_UNKNOWN19" },
    { D2GS_S_UNKNOWN20, "D2GS_S_UNKNOWN20" },
    { D2GS_S_UNKNOWN21, "D2GS_S_UNKNOWN21" },
    { D2GS_S_UNKNOWN22, "D2GS_S_UNKNOWN22" },
    { D2GS_S_UNKNOWN23, "D2GS_S_UNKNOWN23" },
    { D2GS_S_UNKNOWN24, "D2GS_S_UNKNOWN24" },
    { D2GS_PLAYERCORPSEASSIGN, "D2GS_PLAYERCORPSEASSIGN" },
    { D2GS_PLAYERPARTYINFO, "D2GS_PLAYERPARTYINFO" },
    { D2GS_PLAYERINPROXIMITY, "D2GS_PLAYERINPROXIMITY" },
    { D2GS_TRADEACTION, "D2GS_TRADEACTION" },
    { D2GS_TRADEACCEPTED, "D2GS_TRADEACCEPTED" },
    { D2GS_GOLDINTRADE, "D2GS_GOLDINTRADE" },
    { D2GS_LOGONRESPONSE, "D2GS_LOGONRESPONSE" },
    { D2GS_ASSIGNSKILLHOTKEY, "D2GS_ASSIGNSKILLHOTKEY" },
    { D2GS_USESCROLL, "D2GS_USESCROLL" },
    { D2GS_SETITEMSTATE, "D2GS_SETITEMSTATE" },
    { D2GS_S_UNKNOWN25, "D2GS_S_UNKNOWN25" },
    { D2GS_ALLYPARTYINFO, "D2GS_ALLYPARTYINFO" },
    { D2GS_UNUSED30, "D2GS_UNUSED30" },
    { D2GS_ASSIGNMERC, "D2GS_ASSIGNMERC" },
    { D2GS_PORTALOWNERSHIP, "D2GS_PORTALOWNERSHIP" },
    { D2GS_UNUSED31, "D2GS_UNUSED31" },
    { D2GS_UNUSED32, "D2GS_UNUSED32" },
    { D2GS_UNUSED33, "D2GS_UNUSED33" },
    { D2GS_UNUSED34, "D2GS_UNUSED34" },
    { D2GS_UNUSED35, "D2GS_UNUSED35" },
    { D2GS_UNUSED36, "D2GS_UNUSED36" },
    { D2GS_UNIQUEEVENTS, "D2GS_UNIQUEEVENTS" },
    { D2GS_NPCWANTSTOINTERACT, "D2GS_NPCWANTSTOINTERACT" },
    { D2GS_PLAYERRELATIONSHIP, "D2GS_PLAYERRELATIONSHIP" },
    { D2GS_RELATIONSHIPUPDATE, "D2GS_RELATIONSHIPUPDATE" },
    { D2GS_ASSIGNPLAYERTOPARTY, "D2GS_ASSIGNPLAYERTOPARTY" },
    { D2GS_CORPSEASSIGN, "D2GS_CORPSEASSIGN" },
    { D2GS_PONG, "D2GS_PONG" },
    { D2GS_PARTYAUTOMAPINFO, "D2GS_PARTYAUTOMAPINFO" },
    { D2GS_S_UNKNOWN26, "D2GS_S_UNKNOWN26" },
    { D2GS_S_UNKNOWN27, "D2GS_S_UNKNOWN27" },
    { D2GS_S_UNKNOWN28, "D2GS_S_UNKNOWN28" },
    { D2GS_BASESKILLLEVELS, "D2GS_BASESKILLLEVELS" },
    { D2GS_LIFEANDMANAUPDATE, "D2GS_LIFEANDMANAUPDATE" },
    { D2GS_WALKVERIFY, "D2GS_WALKVERIFY" },
    { D2GS_WEAPONSWITCH, "D2GS_WEAPONSWITCH" },
    { D2GS_S_UNKNOWN29, "D2GS_S_UNKNOWN29" },
    { D2GS_SKILLTRIGGERED, "D2GS_SKILLTRIGGERED" },
    { D2GS_S_UNKNOWN30, "D2GS_S_UNKNOWN30" },
    { D2GS_MERCRELATED, "D2GS_MERCRELATED" },
    { D2GS_ITEMACTIONWORLD, "D2GS_ITEMACTIONWORLD" },
    { D2GS_ITEMACTIONOWNED, "D2GS_ITEMACTIONOWNED" },
    { D2GS_BMERCATTRIBUTE, "D2GS_BMERCATTRIBUTE" },
    { D2GS_WMERCATTRIBUTE, "D2GS_WMERCATTRIBUTE" },
    { D2GS_DWMERCATTRIBUTE, "D2GS_DWMERCATTRIBUTE" },
    { D2GS_BMERCADDEXP, "D2GS_BMERCADDEXP" },
    { D2GS_WMERCADDEXP, "D2GS_WMERCADDEXP" },
    { D2GS_S_UNKNOWN31, "D2GS_S_UNKNOWN31" },
    { D2GS_S_UNKNOWN32, "D2GS_S_UNKNOWN32" },
    { D2GS_S_UNKNOWN33, "D2GS_S_UNKNOWN33" },
    { D2GS_S_UNKNOWN34, "D2GS_S_UNKNOWN34" },
    { D2GS_DELAYEDSTATE, "D2GS_DELAYEDSTATE" },
    { D2GS_SETSTATE, "D2GS_SETSTATE" },
    { D2GS_ENDSTATE, "D2GS_ENDSTATE" },
    { D2GS_STATEADD, "D2GS_STATEADD" },
    { D2GS_NPCHEAL, "D2GS_NPCHEAL" },
    { D2GS_ASSIGNNPC, "D2GS_ASSIGNNPC" },
    { D2GS_S_UNKNOWN35, "D2GS_S_UNKNOWN35" },
    { D2GS_WARDENREQUEST, "D2GS_WARDENREQUEST" },
    { D2GS_NEGOTIATECOMPRESSION, "D2GS_NEGOTIATECOMPRESSION" },
    { D2GS_GAMECONNECTIONTERMINATED, "D2GS_GAMECONNECTIONTERMINATED" },
    { D2GS_S_UNKNOWN36, "D2GS_S_UNKNOWN36" },
    { D2GS_S_UNKNOWN37, "D2GS_S_UNKNOWN37" },
    { D2GS_IPBAN, "D2GS_IPBAN" },
    { D2GS_S_UNKNOWN38, "D2GS_S_UNKNOWN38" },
    { D2GS_OVERHEAD, "D2GS_OVERHEAD" },
    { D2GS_UNKOWNFF, "D2GS_UNKOWNFF"  },
    { 0x00, NULL }
};

static const value_string classes_strings[] = {
    { 0x01, "Sorceress" },
    { 0x00, NULL }
};

static const value_string unit_strings[] = {
    { 0x00, "Sorceress" },
    { 0x00, NULL }
};

static const value_string act_strings[] = {
    { 0x00, "Act 1 - Rogue Encampment" },
    { 0x01, "Act 2 - Lut Gholein" },
    { 0x02, "Act 3 - Kurast Docks" },
    { 0x03, "Act 4 - Pandemonium Fortress" },
    { 0x04, "Act 5 - Harrogath" },
};

static int dissect_d2gs_s_to_c(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint total_len = tvb_captured_length(tvb);

    proto_item *d2gs_proto_item = proto_tree_add_protocol_format(tree, proto_d2gs, tvb, 0, -1, "D2GS Packets");
    proto_tree *d2gs_tree = proto_item_add_subtree(d2gs_proto_item, ett_d2gs);

    guint offset = 0;
    gint num_pkts = 0;
    while (offset < total_len) {
        uint8_t type = tvb_get_gint8(tvb, offset);
        tvbuff_t *nexttvb = tvb_new_subset_remaining(tvb, offset);
        num_pkts++;

        proto_tree *cmd_tree = NULL;
        proto_item *cmd_item = NULL;
        cmd_tree = proto_tree_add_subtree_format(d2gs_tree, nexttvb, 0, -1, ett_cmd, &cmd_item, "%s", d2gs_stypes[type].strptr);
        proto_tree_add_item(cmd_tree, hf_d2gs_type, nexttvb, 0, 1, ENC_LITTLE_ENDIAN);

        switch (type) {
        case D2GS_CREATECLIENTPLAYER:
            {
                proto_tree_add_item(cmd_item, hf_createclientplayer_guid, nexttvb, 1, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_item, hf_createclientplayer_class, nexttvb, 5, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_item, hf_createclientplayer_name, nexttvb, 6, 16, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_item, hf_createclientplayer_x, nexttvb, 22, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_item, hf_createclientplayer_y, nexttvb, 24, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 26);
                offset += 26;
            }
            break;
        case D2GS_STATEADD:
            {
                proto_tree_add_item(cmd_tree, hf_stateadd_unit, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_stateadd_guid, nexttvb, 2, 4, ENC_LITTLE_ENDIAN);

                proto_tree *streamtree = NULL;
                proto_item *streamitem = NULL;
                streamtree = proto_tree_add_subtree(cmd_tree, nexttvb, 6, -1, ett_stream, &streamitem, "State Stream");

                guint difflen;
                proto_tree_add_item_ret_uint(streamtree, hf_stateadd_streamlen, nexttvb, 6, 1, ENC_LITTLE_ENDIAN, &difflen);
                difflen -= 7;
                proto_tree_add_item(streamtree, hf_stateadd_streambytes, nexttvb, 7, difflen, ENC_NA);
                proto_item_set_len(streamitem, 1 + difflen);
                proto_item_set_len(cmd_item, 7 + difflen);
                offset += (7 + difflen);
            }
            break;
        case D2GS_PLAYERINPROXIMITY:
            {
                proto_tree_add_item(cmd_tree, hf_pip_unit, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_pip_guid, nexttvb, 2, 4, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 6);
                offset += 6;
            }
            break;
        case D2GS_BASESKILLLEVELS:
            {
                guint num_skills;
                proto_tree_add_item_ret_uint(cmd_tree, hf_baseskill_amt, nexttvb, 1, 1, ENC_LITTLE_ENDIAN, &num_skills);
                proto_tree_add_item(cmd_tree, hf_baseskill_playerid, nexttvb, 2, 4, ENC_LITTLE_ENDIAN);

                proto_tree *skill_tree = NULL;
                proto_item *skill_item = NULL;
                tvbuff_t *skill_tvb = tvb_new_subset_remaining(nexttvb, 6);
                skill_tree = proto_tree_add_subtree(cmd_tree, skill_tvb, 0, num_skills * 3, ett_skill, &skill_item, "Base Skill Levels Array");
                for (guint i = 0; i < num_skills; i++) {
                    proto_tree_add_item(skill_tree, hf_baseskill_skill, skill_tvb, i * 3, 2, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(skill_tree, hf_baseskill_skilllvl, skill_tvb, (i * 3) + 2, 1, ENC_LITTLE_ENDIAN);
                }
                proto_item_set_len(cmd_item, 6 + (3 * num_skills));
                offset += 6 + (3 * num_skills);
            }
            break;
        case D2GS_UPDATEITEMSKILL:
            {
                proto_tree_add_item(cmd_tree, hf_updateitemskill_unk1, nexttvb, 1, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemskill_guid, nexttvb, 3, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemskill_skill, nexttvb, 7, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemskill_amt, nexttvb, 9, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemskill_unk2, nexttvb, 10, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 12);
                offset += 12;
            }
            break;
        case D2GS_UPDATEITEMOSKILL:
            {
                proto_tree_add_item(cmd_tree, hf_updateitemoskill_unk1, nexttvb, 1, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemoskill_guid, nexttvb, 3, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemoskill_skill, nexttvb, 7, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemoskill_baselevel, nexttvb, 9, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemoskill_bonusamt, nexttvb, 10, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_updateitemoskill_unk2, nexttvb, 11, 1, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 12);
                offset += 12;
            }
            break;
        case D2GS_SETSKILL:
            {
                proto_tree_add_item(cmd_tree, hf_setskill_unit, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_setskill_guid, nexttvb, 2, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_setskill_hand, nexttvb, 6, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_setskill_skill, nexttvb, 7, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_setskill_unk1, nexttvb, 9, 4, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 13);
                offset += 13;
            }
            break;
        case D2GS_S_UNKNOWN13:
            {
                proto_tree_add_item(cmd_tree, hf_unknown13_array, nexttvb, 1, 37, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 38);
                offset += 38;
            }
            break;
        case D2GS_QUESTINFO:
            {
                proto_tree_add_item(cmd_tree, hf_questinfo_array, nexttvb, 1, 102, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 103);
                offset += 103;
            }
            break;
        case D2GS_GAMEQUESTINFO:
            {
                proto_tree_add_item(cmd_tree, hf_gamequestinfo_array, nexttvb, 1, 96, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 97);
                offset += 97;
            }
            break;
        case D2GS_GAMEHANDSHAKE:
            {
                proto_tree_add_item(cmd_tree, hf_gamehandshake_unit, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_gamehandshake_guid, nexttvb, 2, 4, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 6);
                offset += 6;
            }
            break;
        case D2GS_S_UNKNOWN14:
            {
                proto_tree_add_item(cmd_tree, hf_unknown14_array, nexttvb, 1, 4, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 5);
                offset += 5;
            }
            break;
        case D2GS_SETBYTEATTR:
            {
                proto_tree_add_item(cmd_tree, hf_setbyteattr_attr, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_setbyteattr_amt, nexttvb, 2, 1, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 3);
                offset += 3;
            }
            break;
        case D2GS_SETWORDATTR:
            {
                proto_tree_add_item(cmd_tree, hf_setwordattr_attr, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_setwordattr_amt, nexttvb, 2, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 4);
                offset += 4;
            }
            break;
        case D2GS_ITEMACTIONWORLD:
            {
                proto_tree_add_item(cmd_tree, hf_itemactionworld_entity, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);

                proto_tree *arraytree = NULL;
                proto_item *arrayitem = NULL;
                arraytree = proto_tree_add_subtree(cmd_tree, nexttvb, 2, -1, ett_array, &arrayitem, "ITEMACTIONWORLD Array");

                guint difflen;
                proto_tree_add_item_ret_uint(arraytree, hf_itemactionworld_arraylen, nexttvb, 2, 1, ENC_LITTLE_ENDIAN, &difflen);
                difflen -= 3;
                proto_tree_add_item(arraytree, hf_itemactionworld_array, nexttvb, 3, difflen, ENC_NA);
                proto_item_set_len(arrayitem, 1 + difflen);
                proto_item_set_len(cmd_item, 3 + difflen);
                offset += (3 + difflen);
            }
            break;
        case D2GS_ITEMACTIONOWNED:
            {
                proto_tree_add_item(cmd_tree, hf_itemactionowned_unknown1, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);

                proto_tree *arraytree = NULL;
                proto_item *arrayitem = NULL;
                arraytree = proto_tree_add_subtree(cmd_tree, nexttvb, 2, -1, ett_array, &arrayitem, "ITEMACTIONOWNED Array");

                guint difflen;
                proto_tree_add_item_ret_uint(arraytree, hf_itemactionowned_arraylen, nexttvb, 2, 1, ENC_LITTLE_ENDIAN, &difflen);
                difflen -= 3;
                proto_tree_add_item(arraytree, hf_itemactionowned_array, nexttvb, 3, difflen, ENC_NA);
                proto_item_set_len(arrayitem, 1 + difflen);
                proto_item_set_len(cmd_item, 3 + difflen);
                offset += (3 + difflen);
            }
            break;
        case D2GS_LIFEANDMANAUPDATE:
            {
                /* 96-bit bitfield unsupported by `proto_tree_add_bitmask`. Split into 2. */
                proto_tree_add_bitmask(cmd_tree, nexttvb, 1, hf_lamu_fields, ett_lamu_fields, lamu_fields, ENC_BIG_ENDIAN);
                proto_tree_add_bitmask(cmd_tree, nexttvb, 6, hf_lamu_fields2, ett_lamu_fields, lamu_fields2, ENC_BIG_ENDIAN);
                proto_item_set_len(cmd_item, 13);
                offset += 13;
            }
            break;
        case D2GS_LOADACT:
            {
                proto_tree_add_item(cmd_tree, hf_loadact_act, nexttvb, 1, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_loadact_drlg_seed, nexttvb, 2, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_loadact_area, nexttvb, 6, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(cmd_tree, hf_loadact_obj_seed, nexttvb, 8, 4, ENC_LITTLE_ENDIAN);
                proto_item_set_len(cmd_item, 13);
                offset += 13;
            }
            break;

        default:
            /* Unknown packet type */
            offset += 1500;
            break;
        }
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%d packets)", num_pkts);
    return offset;
}

int dissect_d2gs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    if (value_is_in_range(tcp_port_range, pinfo->srcport)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "D2GS");
        col_set_str(pinfo->cinfo, COL_INFO, "S> ");
        dissect_d2gs_s_to_c(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

void proto_register_d2gs(void)
{
    static gint *ett[] = {
        &ett_d2gs,
        &ett_cmd,
        &ett_stream,
        &ett_array,
        &ett_skill,
        &ett_lamu_fields,
    };

    static hf_register_info hf[] = {
        { &hf_d2gs_type, { "Type", "d2gs.type", FT_UINT8, BASE_HEX, VALS(d2gs_stypes), 0x0, "The D2GS packet type.", HFILL }},

        { &hf_createclientplayer_guid, { "GUID", "d2gs.guid", FT_UINT32, BASE_HEX, NULL, 0x0, "The player GUID", HFILL }},
        { &hf_createclientplayer_class, { "CLASS", "d2gs.class", FT_UINT8, BASE_HEX, VALS(classes_strings), 0x0, "The player class", HFILL }},
        { &hf_createclientplayer_name, { "NAME", "d2gs.name", FT_STRINGZPAD, BASE_NONE, NULL, 0x0, "The player name", HFILL }},
        { &hf_createclientplayer_x, { "PLAYER X", "d2gs.playerx", FT_UINT16, BASE_HEX, NULL, 0x0, "The player X position", HFILL }},
        { &hf_createclientplayer_y, { "PLAYER Y", "d2gs.playery", FT_UINT16, BASE_HEX, NULL, 0x0, "The player Y position", HFILL }},

        { &hf_stateadd_unit, { "UNITTYPE", "d2gs.unittype", FT_UINT8, BASE_HEX, VALS(unit_strings), 0x0, "The unit type", HFILL }},
        { &hf_stateadd_guid, { "GUID", "d2gs.guid", FT_UINT32, BASE_HEX, NULL, 0x0, "The player GUID", HFILL }},
        { &hf_stateadd_streamlen, { "STREAMLEN", "d2gs.stream.len", FT_UINT8, BASE_HEX, NULL, 0x0, "The stream length", HFILL }},
        { &hf_stateadd_streambytes, { "STREAM", "d2gs.stream.bytes", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, "The stream bytes", HFILL }},

        { &hf_pip_unit, { "UNITTYPE", "d2gs.unittype", FT_UINT8, BASE_HEX, VALS(unit_strings), 0x0, "The unit type", HFILL }},
        { &hf_pip_guid, { "GUID", "d2gs.guid", FT_UINT32, BASE_HEX, NULL, 0x0, "The player GUID", HFILL }},

        { &hf_baseskill_amt, { "NUM SKILLS", "d2gs.baseskill.amount", FT_UINT8, BASE_HEX, NULL, 0x0, "Number of skill levels", HFILL }},
        { &hf_baseskill_playerid, { "PLAYER ID", "d2gs.playerid", FT_UINT32, BASE_HEX, NULL, 0x0, "Player ID", HFILL }},
        { &hf_baseskill_skill, { "SKILL", "d2gs.skill", FT_UINT16, BASE_HEX, NULL, 0x0, "Skill", HFILL }},
        { &hf_baseskill_skilllvl, { "LEVEL", "d2gs.skill.level", FT_UINT8, BASE_DEC, NULL, 0x0, "Skill Level", HFILL }},

        { &hf_updateitemskill_unk1, {"UKNOWN1", "d2gs.updateitemskill.unknown1", FT_UINT16, BASE_HEX, NULL, 0x0, "Uknown1", HFILL }},
        { &hf_updateitemskill_guid, { "GUID", "d2gs.guid", FT_UINT32, BASE_HEX, NULL, 0x0, "The player GUID", HFILL }},
        { &hf_updateitemskill_skill, { "SKILL", "d2gs.itemskill", FT_UINT16, BASE_HEX, NULL, 0x0, "Skill", HFILL }},
        { &hf_updateitemskill_amt, { "SKILL LVL", "d2gs.itemskill.amount", FT_UINT8, BASE_HEX, NULL, 0x0, "Skill level", HFILL }},
        { &hf_updateitemskill_unk2, {"UKNOWN2", "d2gs.updateitemskill.unknown2", FT_UINT16, BASE_HEX, NULL, 0x0, "Uknown2", HFILL }},

        { &hf_updateitemoskill_unk1, {"UKNOWN1", "d2gs.updateitemskill.unknown1", FT_UINT16, BASE_HEX, NULL, 0x0, "Uknown1", HFILL }},
        { &hf_updateitemoskill_guid, { "GUID", "d2gs.guid", FT_UINT32, BASE_HEX, NULL, 0x0, "The player GUID", HFILL }},
        { &hf_updateitemoskill_skill, { "SKILL", "d2gs.skill", FT_UINT16, BASE_HEX, NULL, 0x0, "Skill", HFILL }},
        { &hf_updateitemoskill_baselevel, { "BASE LVL", "d2gs.baselevel", FT_UINT8, BASE_HEX, NULL, 0x0, "Base level", HFILL }},
        { &hf_updateitemoskill_bonusamt, {"BONUS AMT", "d2gs.bonusamt", FT_UINT8, BASE_HEX, NULL, 0x0, "Bonus amount", HFILL }},
        { &hf_updateitemoskill_unk2, {"UKNOWN2", "d2gs.updateitemskill.unknown2", FT_UINT8, BASE_HEX, NULL, 0x0, "Uknown2", HFILL }},

        { &hf_setskill_unit, {"UNITTYPE", "d2gs.unittype", FT_UINT8, BASE_HEX, NULL, 0x0, "The unit type", HFILL }},
        { &hf_setskill_guid, { "GUID", "d2gs.guid", FT_UINT32, BASE_HEX, NULL, 0x0, "The player GUID", HFILL }},
        { &hf_setskill_hand, { "HAND", "d2gs.hand", FT_UINT8, BASE_HEX, NULL, 0x0, "Which hand", HFILL }},
        { &hf_setskill_skill, { "SKILL", "d2gs.skill", FT_UINT16, BASE_HEX, NULL, 0x0, "Skill", HFILL }},
        { &hf_setskill_unk1, { "UNKNOWN1", "d2gs.setskill.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0, "Uknown1", HFILL }},

        { &hf_unknown13_array, {"ARRAY", "d2gs.unknown13.array", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, "The array bytes", HFILL}},

        { &hf_questinfo_array, {"ARRAY", "d2gs.questinfo.array", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, "The array bytes", HFILL}},

        { &hf_gamequestinfo_array, {"ARRAY", "d2gs.gamequestinfo.array", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, "The array bytes", HFILL}},

        { &hf_gamehandshake_unit, { "UNITTYPE", "d2gs.unittype", FT_UINT8, BASE_HEX, VALS(unit_strings), 0x0, "The unit type", HFILL }},
        { &hf_gamehandshake_guid, { "GUID", "d2gs.guid", FT_UINT32, BASE_HEX, NULL, 0x0, "The player GUID", HFILL }},

        { &hf_unknown14_array, {"ARRAY", "d2gs.unknown14.array", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, "The array bytes", HFILL}},

        { &hf_setbyteattr_attr, {"ATTRIBUTE", "d2gs.attribute", FT_UINT8, BASE_HEX, NULL, 0x0, "The attribute", HFILL}},
        { &hf_setbyteattr_amt, {"AMOUNT", "d2gs.attribute.amount", FT_UINT8, BASE_HEX, NULL, 0x0, "The attribute amount", HFILL}},

        { &hf_setwordattr_attr, {"ATTRIBUTE", "d2gs.attribute", FT_UINT8, BASE_HEX, NULL, 0x0, "The attribute", HFILL}},
        { &hf_setwordattr_amt, {"AMOUNT", "d2gs.attribute.amount", FT_UINT16, BASE_HEX, NULL, 0x0, "The attribute amount", HFILL}},

        { &hf_itemactionworld_entity, { "ENTITY", "d2gs.itemactionworld.entity", FT_UINT8, BASE_HEX, NULL, 0x0, "The entity type", HFILL }},
        { &hf_itemactionworld_arraylen, { "ARRAY LENGTH", "d2gs.itemactionworld.arraylen", FT_UINT8, BASE_HEX, NULL, 0x0, "The array length", HFILL }},
        { &hf_itemactionworld_array, { "ARRAY", "d2gs.itemactionworld.array", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, "The array bytes", HFILL }},

        { &hf_itemactionowned_unknown1, { "UNKNOWN1", "d2gs.itemactionowned.unknown1", FT_UINT8, BASE_HEX, NULL, 0x0, "UNKNOWN1", HFILL }},
        { &hf_itemactionowned_arraylen, { "ARRAY LENGTH", "d2gs.itemactionowned.arraylen", FT_UINT8, BASE_HEX, NULL, 0x0, "The array length", HFILL }},
        { &hf_itemactionowned_array, { "ARRAY", "d2gs.itemactionowned.array", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, "The array bytes", HFILL }},

        { &hf_lamu_fields, { "Life-Mana-Stamina", "d2gs.lifeandmanaupdate", FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lamu_life, { "LIFE", "d2gs.life", FT_UINT48, BASE_DEC, NULL, 0xfffe00000000, "Player life", HFILL }},
        { &hf_lamu_mana, { "MANA", "d2gs.mana", FT_UINT48, BASE_DEC, NULL, 0x0001fffc0000, "Player mana", HFILL }},
        { &hf_lamu_stamina, { "STAMINA", "d2gs.stamina", FT_UINT48, BASE_DEC, NULL, 0x00000006fff8, "Player stamina", HFILL }},
        { &hf_lamu_fields2, { "X,Y,UNKNOWN", "d2gs.lifeandmanaupdate", FT_UINT56, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_lamu_x, { "PLAYER X", "d2gs.playerx", FT_UINT56, BASE_DEC, NULL, 0x7FFF8000000000, "Player X position", HFILL }},
        { &hf_lamu_y, { "PLAYER Y", "d2gs.playery", FT_UINT56, BASE_DEC, NULL, 0x00007FFF800000, "Player Y position", HFILL }},
        { &hf_lamu_unk, { "UNKNOWN", "d2gs.lifeandmanaupdate.unk", FT_UINT56, BASE_DEC, NULL, 0x000000007fffff, "Unknown", HFILL }},

        { &hf_loadact_act, { "ACT", "d2gs.act", FT_UINT8, BASE_DEC, VALS(act_strings), 0x0, "Player's act", HFILL }},
        { &hf_loadact_drlg_seed, { "DRLG SEED", "d2gs.seed.drlg", FT_UINT32, BASE_HEX, NULL, 0x0, "DRLG map seed", HFILL }},
        { &hf_loadact_area, { "AREA ID", "d2gs.area", FT_UINT16, BASE_HEX, NULL, 0x0, "Map area", HFILL }},
        { &hf_loadact_obj_seed, { "OBJECT CONTROL SEED", "d2gs.seed.objectcontrol", FT_UINT32, BASE_HEX, NULL, 0x0, "ObjectControl seed", HFILL }},
    };

    proto_d2gs = proto_register_protocol("D2GS Protocol", "D2GS", "d2gs");
    proto_register_field_array(proto_d2gs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    d2gs_handle = register_dissector("d2gs", dissect_d2gs, proto_d2gs);
}

void
proto_reg_handoff_d2gs(void)
{
    dissector_add_uint_with_preference("tcp.port", D2GS_PORT, d2gs_handle);
}
