from ipaddress import ip_address

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
    
clear_all(verbose=True)

CPU_PORT_1 = 64

################ Add ports ##########################

# TODO from yaml
# enable internal CPU ports
pm.port.add(DEV_PORT=64, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)
pm.port.add(DEV_PORT=66, SPEED="BF_SPEED_10G", FEC="BF_FEC_TYP_NONE", PORT_ENABLE=True)

# front panel port 2/0 directly attached to server
pm.port.add(DEV_PORT=140, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)

# front panel port 31/0 directly connected to 32/0
pm.port.add(DEV_PORT=128, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)
pm.port.add(DEV_PORT=136, SPEED="BF_SPEED_100G", FEC="BF_FEC_TYP_RS", PORT_ENABLE=True)

# P/PT means pipe / port. This is the number you are supposed to use in
# all ucli cmds e.g., ibuf -d 0 -p 1 -m 8 is used to check counters relative 
# to front panel port 32/0


# alternative is following path bfrt.tf1.tm.port.cfg.get(dev_port=64)
port.mod(CPU_PORT_1, COPY_TO_CPU_PORT_ENABLE=True)

################ Add table entries ######################

icmp_flow = p4.Ingress.icmp_flow
tcp_flow = p4.Ingress.tcp_flow
udp_flow = p4.Ingress.udp_flow

tcp_flow.idle_table_set_poll(enable=False)
tcp_flow.idle_table_set_poll(enable=True)

udp_flow.idle_table_set_poll(enable=False)
udp_flow.idle_table_set_poll(enable=True)

icmp_flow.idle_table_set_poll(enable=False)
icmp_flow.idle_table_set_poll(enable=True)


# def aging_cb(dev_id, pipe_id, direction, parser_id, entry, _):
#     src_addr = entry.key[b'hdr.ipv4.src_addr']
#     dst_addr = entry.key[b'hdr.ipv4.dst_addr']
#     print(f"Aging out: src_addr={src_addr}, dst_addr={dst_addr}")
#     entry.remove()


# icmp_flow.idle_table_set_notify(enable=False)
# icmp_flow.idle_table_set_notify(enable=True, 
#                                 callback=aging_cb,
#                                 interval=5000,
#                                 min_ttl=5000, 
#                                 max_ttl=20000)

# tcp_flow.idle_table_set_notify(enable=False)
# tcp_flow.idle_table_set_notify(enable=True, 
#                                 callback=aging_cb,
#                                 interval=5000,
#                                 min_ttl=5000, 
#                                 max_ttl=20000)

# udp_flow.idle_table_set_notify(enable=False)
# udp_flow.idle_table_set_notify(enable=True, 
#                                 callback=aging_cb,
#                                 interval=5000,
#                                 min_ttl=5000, 
#                                 max_ttl=20000)

# print("Aging callback registered")


bfrt.complete_operations()


# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table tcp_flow:")
tcp_flow.info()
print ("Table udp_flow:")
udp_flow.info()
print ("Table icmp_flow:")
icmp_flow.info()

                       