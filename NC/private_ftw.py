#!/usr/bin/env python

import os, xmltodict, argparse


def print_instances(xml_config):
    """

    function to display the instances from the network global XML config

    """
    print "XML - Instances found"
    instances = xml_config['network-data']['instances']['instance']
    for instance in instances:
        instance = dict(instance)
        if 'publicIp' in instance.keys():
            print instance['@name'], instance['privateIp'], instance['macAddress'], instance['publicIp']
        else:
            print instance['@name'], instance['privateIp'], instance['macAddress']


def gather_instances(xml_config):
    """

    function to display the instances from the network global XML config

    """
    instances_list = []
    instances = xml_config['network-data']['instances']['instance']
    for instance in instances:
        instance = dict(instance)
        instances_list.append(instance)
    return instances_list

def insert_router_option(instance_mac, pv_gateway_ip, file_path="euca-dhcp.conf"):
    """

    Function which will read and replace the specific lines for non-public instances

    """
    old_config_txt = ""
    with open(file_path, 'r') as fd_old:
        old_config_txt = fd_old.readlines()

    new_config_txt = ""
    for index, line in enumerate(old_config_txt):
        new_config_txt += line
        if (line.find(instance_mac.upper()) > 0 and
            old_config_txt[index +1].find(pv_gateway_ip) < 0):
            new_config_txt += "  option routers %s;\n" % (pv_gateway_ip)

    with open(file_path, 'w') as fd_new:
        fd_new.write(new_config_txt)

def get_local_instances():
    """

    Checks if the instance is on the local NC

    """

    with os.popen("virsh list | grep i- | awk '{print $2}'") as cmd_fd:
        res = cmd_fd.read()
    res = res.split('\n')
    print res, type(res)
    return res
    
def reload_dhcp():
    """

    STUPID - Would have prefered signal()

    """

    os.system('killall dhcpd')
    os.system('/usr/sbin/dhcpd -cf //var/run/eucalyptus/net/euca-dhcp.conf -lf //var/run/eucalyptus/net/euca-dhcp.leases -pf //var/run/eucalyptus/net/euca-dhcp.pid -tf //var/run/eucalyptus/net/euca-dhcp.trace 2>&1 >/dev/null')


def apply(xml_path, pv_gateway_ip, dhcp_path):
    """
    
    Function that uses the others to apply and run
    
    """

    with open(xml_path, 'r') as fd:
        xml_config_file = fd.read()
    if xml_config_file:
        xml_config_dic = xmltodict.parse(xml_config_file)

    instances_xml_list = gather_instances(xml_config_dic)
    instances_virsh_list = get_local_instances()

    for instance_xml in instances_xml_list:
        if instance_xml['@name'] in instances_virsh_list:
            if not 'publicIp' in instance_xml.keys():
                insert_router_option(instance_xml['macAddress'], pv_gateway_ip, dhcp_path)
            reload_dhcp()
        else:
            pass
    

def main():

    parser = argparse.ArgumentParser(description='Auto-update DHCP config for private only instances')
    parser.add_argument("-x", "--xml-file", metavar="xmlfile", type=str, help="path to the eucanted global XML config", required=True)
    parser.add_argument("-d", "--dhcp-config", metavar="dhcpconf", type=str, help="path to the euca dhcp config file", required=True)
    parser.add_argument("-g", "--gateway", metavar="gateway", type=str, help="gateway IP to be used by instances", required=True)

    args = parser.parse_args()
    apply(args.xml_file, args.gateway, args.dhcp_config)


if __name__ == '__main__':
    main()
