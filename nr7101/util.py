def parse_traffic_object(obj):
    ret = {}
    for iface, iface_st in zip(obj["ipIface"], obj["ipIfaceSt"]):
        ret[iface["X_ZYXEL_IfName"]] = iface_st
    return ret