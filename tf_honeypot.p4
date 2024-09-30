/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "include/definition.p4"
#include "include/header.p4"
#include "include/parser.p4"
#include "include/ingress.p4"
#include "include/egress.p4"

/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
