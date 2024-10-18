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
    
# clear_all(verbose=True)

CPU_PORT_1 = 64
MIRROR_PORT = 1

SESSION_ID = 12
TRUNCATE_SIZE = 128

################ Add table entries ######################

active_host_tbl = p4.Ingress.active_host_tbl

active_host_tbl.idle_table_set_poll(enable=False)
active_host_tbl.idle_table_set_poll(enable=True)

mirror_fwd_tbl = p4.Ingress.mirror_fwd
mirror_fwd_tbl.clear()
mirror_fwd_tbl.add_with_set_mirror(ingress_port=CPU_PORT_1, 
                                   dest_port=MIRROR_PORT, ing_mir_ses=SESSION_ID)

mirror_cfg_tbl = bfrt.mirror.cfg
mirror_cfg_tbl.clear()
mirror_cfg_tbl.add_with_normal(sid=SESSION_ID,
                               session_enable=True,
                               direction="INGRESS",
                               ucast_egress_port=MIRROR_PORT,
                               ucast_egress_port_valid=True,
                               max_pkt_len=TRUNCATE_SIZE)


bfrt.complete_operations()


# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table active_host_tbl:")
active_host_tbl.info()

                       