from ipaddress import ip_address
import os

# Loading whitelist from configuration
white_list = []
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'remote_whitelist.csv')) as f:
    for line in f.readlines():
        white_list.append(line.replace("\n", "").split(","))


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

CPU_PORT_1 = 64

################ Add ports ##########################

# TODO from yaml
# enable internal CPU ports
pm.port.add(DEV_PORT=64, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)
pm.port.add(DEV_PORT=66, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)

# front panel port 2/0 directly attached to server
pm.port.add(DEV_PORT=140, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)

# front panel port 28/0 directly attached to anonymizer 
pm.port.add(DEV_PORT=160, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)

# front panel port 31/0 directly connected to 32/0
pm.port.add(DEV_PORT=128, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)
pm.port.add(DEV_PORT=136, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)

# P/PT means pipe / port. This is the number you are supposed to use in
# all ucli cmds e.g., ibuf -d 0 -p 1 -m 8 is used to check counters relative 
# to front panel port 32/0


# alternative is following path bfrt.tf1.tm.port.cfg.get(dev_port=64)
port.mod(CPU_PORT_1, COPY_TO_CPU_PORT_ENABLE=True)

################ Add table entries ######################

active_host_tbl = p4.Ingress.active_host_tbl
active_host_tbl.clear()

whitelist_tbl = p4.Ingress.whitelist_tbl
whitelist_tbl.clear()
for (ip, port, proto) in white_list:
    whitelist_tbl.add_with_drop(external_ip=ip,
                                external_port=port,
                                ip_protocol=proto)

################ Mirroring Setting ######################

INCOMING_PORT = 160

MIRROR_IN_PORT = 140
MIRROR_OUT_PORT = 140

PROXY_DST_MAC = "52:54:00:5b:57:5c"

SESSION_ID = 12
TRUNCATE_SIZE = 128

mirror_fwd_tbl = p4.Ingress.mirror_fwd
mirror_fwd_tbl.clear()
mirror_fwd_tbl.add_with_set_ing_mirror(ingress_port=MIRROR_IN_PORT, 
                                       ing_mir_ses=SESSION_ID,
                                       dst_mac = PROXY_DST_MAC)
mirror_fwd_tbl.add_with_set_ing_mirror(ingress_port=INCOMING_PORT, 
                                       ing_mir_ses=13,
                                       dst_mac = PROXY_DST_MAC)

mirror_cfg_tbl = bfrt.mirror.cfg
mirror_cfg_tbl.clear()
mirror_cfg_tbl.add_with_normal(sid=SESSION_ID,
                               session_enable=True,
                               direction="INGRESS",
                               ucast_egress_port=MIRROR_OUT_PORT,
                               ucast_egress_port_valid=True,
                               max_pkt_len=TRUNCATE_SIZE)
mirror_cfg_tbl.add_with_normal(sid=13,
                               session_enable=True,
                               direction="INGRESS",
                               ucast_egress_port=MIRROR_OUT_PORT,
                               ucast_egress_port_valid=True,
                               max_pkt_len=TRUNCATE_SIZE)


bfrt.complete_operations()


# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table active_host_tbl:")
active_host_tbl.info()

print ("Table whitelist_tbl:")
whitelist_tbl.info()         