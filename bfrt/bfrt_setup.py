from ipaddress import ip_address
import json
import os

_BFRT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_setup_config():
    path = os.path.join(_BFRT_DIR, 'bfrt_setup.json')
    with open(path) as f:
        return json.load(f)

p4 = bfrt.tf_honeypot.pipe
pm = bfrt.port
port = bfrt.pre.port

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    
    def _clear(table, verbose=False, batching=False):
        if verbose:
            print("Clearing table {:<40} ... ".
                  format(table['full_name']), end='', flush=True)
        try:    
            entries = table['node'].get(regex=True, print_ents=False)
            try:
                if batching:
                    bfrt.batch_begin()
                for entry in entries:
                    entry.remove()
            except Exception as e:
                print("Problem clearing table {}: {}".format(
                    table['name'], e.sts))
            finally:
                if batching:
                    bfrt.batch_end()
        except Exception as e:
            if e.sts == 6:
                if verbose:
                    print('(Empty) ', end='')
        finally:
            if verbose:
                print('Done')

        # Optionally reset the default action, but not all tables
        # have that
        try:
            table['node'].reset_default()
        except:
            pass
    
    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members
    

    # Clear Match Tables
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)

    # Clear Selectors
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)
            
    # Clear Action Profiles
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['ACTION_PROFILE']:
            _clear(table, verbose=verbose, batching=batching)
    
# clear_all(verbose=True)

_SETUP = _load_setup_config()
TRAFFIC_MODE = _SETUP['traffic_mode']

CPU_PORT_1 = 64

################ Add ports ##########################

# enable internal CPU ports
pm.port.add(DEV_PORT=64, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)
pm.port.add(DEV_PORT=66, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)

# front panel port 2/0 directly attached to server
pm.port.add(DEV_PORT=140, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)


# front panel port 31/0 directly connected to 32/0
# pm.port.add(DEV_PORT=128, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)
# pm.port.add(DEV_PORT=136, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)

# P/PT means pipe / port. This is the number you are supposed to use in
# all ucli cmds e.g., ibuf -d 0 -p 1 -m 8 is used to check counters relative 
# to front panel port 32/0


# alternative is following path bfrt.tf1.tm.port.cfg.get(dev_port=64)
port.mod(CPU_PORT_1, COPY_TO_CPU_PORT_ENABLE=True)

# Loading whitelist from configuration
white_num = 0
white_list = []
with open(os.path.join(_BFRT_DIR, 'remote_whitelist.csv')) as f:
    for line in f.readlines():
        white_list.append(line.replace("\n", "").split(","))
white_list = white_list[:white_num]

############## Live vs replay traffic (from bfrt_setup.json) #####################
_modes = _SETUP['modes']
if TRAFFIC_MODE not in _modes:
    raise ValueError(
        'traffic_mode {!r} not found in modes; valid: {}'.format(
            TRAFFIC_MODE, sorted(_modes.keys())))
_mode_cfg = _modes[TRAFFIC_MODE]
internal_nets = [tuple(p) for p in _mode_cfg['internal_nets']]
INCOMING_PORT = _mode_cfg['incoming_dev_port']

if TRAFFIC_MODE == 'live':
    if _mode_cfg.get('add_incoming_port', True):
        pm.port.add(
            DEV_PORT=_mode_cfg['incoming_dev_port'],
            SPEED='BF_SPEED_100G',
            FEC='BF_FEC_TYP_RS',
            PORT_ENABLE=True,
        )
elif TRAFFIC_MODE == 'replay':
    for _dp in _mode_cfg.get('delete_dev_ports', []):
        try:
            pm.port.delete(DEV_PORT=_dp)
        except Exception:
            pass
else:
    raise ValueError('traffic_mode must be "live" or "replay", got {!r}'.format(TRAFFIC_MODE))

################ Add White list ######################

active_host_tbl = p4.Ingress.active_host_tbl
active_host_tbl.clear()

whitelist_tbl = p4.Ingress.whitelist_tbl
whitelist_tbl.clear()
for (ip, port, proto, _) in white_list:
    whitelist_tbl.add_with_drop(external_ip=ip,
                                external_port=port,
                                ip_protocol=proto)
    
################ Add Internal Nets ######################
internal_ip_check_tbl = p4.Ingress.internal_ip_check
internal_ip_check_tbl.clear()

for net in internal_nets:
    internal_ip_check_tbl.add_with_set_src_internal(src_addr=net[0], src_addr_mask=net[1], MATCH_PRIORITY=10)
    internal_ip_check_tbl.add_with_set_dst_internal(dst_addr=net[0], dst_addr_mask=net[1], MATCH_PRIORITY=10)


################ Add forwarding (controller + ECMP selector from bfrt_setup.json) ######################
_ctrl = _SETUP['controller']
CONTROLLER_PORT = _ctrl['out_port']
_dst_macs = _ctrl['dst_macs']
if not _dst_macs:
    raise ValueError('controller.dst_macs must be a non-empty list')

_member_idx = _ctrl.get('selector_member_indices')
if _member_idx is None:
    _member_idx = list(range(len(_dst_macs)))
_sel_gid = int(_ctrl.get('selector_group_id', 0))
_max_group = int(_ctrl.get('selector_max_group_size', 16))

for _mid in _member_idx:
    if _mid < 0 or _mid >= len(_dst_macs):
        raise ValueError(
            'selector_member_indices {!r} out of range for dst_macs length {}'.format(
                _member_idx, len(_dst_macs)))
if len(_member_idx) > _max_group:
    raise ValueError(
        'selector uses {} members but selector_max_group_size is {}'.format(
            len(_member_idx), _max_group))

# Action profile: one member per dst_mac index; selector references a subset (or all).
ap  = p4.Ingress.send_to_controller_ap
sel = p4.Ingress.send_to_controller_selector
tbl = p4.Ingress.fwd_controller_tbl
tbl.clear()
sel.clear()
ap.clear()

for _i, _mac in enumerate(_dst_macs):
    ap.add_with_send_to_controller(
        ACTION_MEMBER_ID=_i, dst_mac=_mac, out_port=CONTROLLER_PORT)

sel.add(
    SELECTOR_GROUP_ID=_sel_gid,
    ACTION_MEMBER_ID=_member_idx,
    ACTION_MEMBER_STATUS=[True] * len(_member_idx),
    MAX_GROUP_SIZE=_max_group,
)
tbl.add(ether_type=0x0800, SELECTOR_GROUP_ID=_sel_gid)

############### Add bloom filter epoch ####################
bloom_epoch_tbl = p4.Ingress.bloom_epoch_tbl
bloom_epoch_tbl.clear()
bloom_epoch_tbl.add_with_set_epoch(bloom_dummy_key=0, epoch=0)

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table active_host_tbl:")
active_host_tbl.info()

print ("Table whitelist_tbl:")
whitelist_tbl.info()         

print ("Table internal_ip_check_tbl:")
internal_ip_check_tbl.info()

# print ("Table mirror_fwd_tbl:")
# mirror_fwd_tbl.info()        