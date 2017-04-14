#!/usr/bin/python

import collections
import datetime
import os
import sys
import table
import xml.etree.ElementTree


# Uncomment and modify the following line so that it specifies all IPv4 and IPv6 addresses
# your mail server uses to send mail.

# OWN_IPS = {'192.168.1.1', '10.0.0.2', '2a01:1234:5678:abcd:efgh::1'}


def scan(path):
    result = []
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            if filename.endswith('.xml'):
                s = filename[:-4].split('!')
                if len(s) == 4:
                    remote, sender, start, end = s
                elif len(s) == 5:
                    remote, sender, start, end, _ = s
                else:
                    print("Skipping file '{}'...".format(os.path.join(dirpath, filename)))
                    continue
                start = datetime.datetime.fromtimestamp(int(start))
                end = datetime.datetime.fromtimestamp(int(end))
                result.append((start, end, sender, remote, os.path.join(dirpath, filename)))
    return sorted(result)


def parse(domain, filename):
    def get(node, name, default=None, expected=False):
        child = node.find(name)
        if child is not None:
            if child.text is None:
                if expected:
                    raise Exception('Expected "{0}" to have child "{1}" with text, but found no text!'.format(node, name))
                return default
            else:
                return child.text
        else:
            if expected:
                raise Exception('Expected "{0}" to have child "{1}", but found none!'.format(node, name))
            return default

    def convert_timestamp(timestamp):
        if timestamp is None:
            return None
        return datetime.datetime.fromtimestamp(int(timestamp))

    e = xml.etree.ElementTree.parse(filename).getroot()
    rm = e.find('report_metadata')
    if rm is None:
        raise Exception('File "{0}" has no metadata reporting'.format(filename))
    rm_org_name = get(rm, 'org_name', None)
    rm_dr = rm.find('date_range')
    rm_start = convert_timestamp(get(rm_dr, 'begin', expected=True))
    rm_end = convert_timestamp(get(rm_dr, 'end', expected=True))
    pp = e.find('policy_published')
    if pp is None:
        raise Exception('File "{0}" has no published policy'.format(filename))
    pp_domain = get(pp, 'domain', expected=True)
    pp_adkim = get(pp, 'adkim', 'r')
    pp_aspf = get(pp, 'aspf', 'r')
    pp_p = get(pp, 'p', 'none')
    pp_sp = get(pp, 'sp', 'none')
    pp_pct = int(get(pp, 'pct', '100'))
    data = []
    for i, r in enumerate(e.findall('record')):
        rr = r.find('row')
        if rr is None:
            raise Exception('File "{0}" has no row data in record {1}'.format(filename, i + 1))
        rr_source_ip = get(rr, 'source_ip', expected=True)
        rr_count = int(get(rr, 'count', 0))
        rrpe = rr.find('policy_evaluated')
        if rrpe is None:
            raise Exception('File "{0}" has no evaluated policy in record {1}'.format(filename, i + 1))
        rrpe_disposition = get(rrpe, 'disposition', expected=True)
        rrpe_dkim = get(rrpe, 'dkim', expected=True)
        rrpe_spf = get(rrpe, 'spf', expected=True)
        ri = r.find('identifiers')
        if ri is None:
            raise Exception('File "{0}" has no identifier in record {1}'.format(filename, i + 1))
        ri_header_from = get(ri, 'header_from', expected=True)
        ra = r.find('auth_results')
        if ra is None:
            raise Exception('File "{0}" has no authentication results in record {1}'.format(filename, i + 1))
        auth_results = {}
        rad = ra.find('dkim')
        if rad is not None:
            auth_results['dkim'] = (get(rad, 'domain', None), get(rad, 'result', None))
        ras = ra.find('spf')
        if ras is not None:
            auth_results['spf'] = (get(ras, 'domain', None), get(ras, 'result', None))
        data.append((rr_source_ip, rr_count, {'disposition': rrpe_disposition, 'dkim': rrpe_dkim, 'spf': rrpe_spf}, ri_header_from, auth_results))
    return (domain, rm_org_name, rm_start, rm_end, {'domain': pp_domain, 'adkim': pp_adkim, 'aspf': pp_aspf, 'p': pp_p, 'sp': pp_sp, 'pct': pp_pct}, data)


def prepare_table(files, own_ips):
    data = collections.defaultdict(list)
    for file in files:
        try:
            domain, org_name, start, end, policy, results = parse(file[3], file[4])
            data[start.date()].append((file, (domain, org_name, start, end, policy, results)))
        except Exception as e:
            print('Error while parsing {0}: {1}'.format(file[4], e))

    def format_result(result):
        if result is None:
            return '---'
        else:
            return '{1}:{0}'.format(result[0], result[1])

    table = [None, None, ('Date', 'Policy and involved domains', '#', 'Source IP', 'Disposition', 'DKIM', 'SPF', 'Header From', 'DKIM auth', 'SPF auth'), None, None]
    for date in sorted(data.keys()):
        policies = collections.defaultdict(list)
        for file, (domain, org_name, start, end, policy, results) in data[date]:
            policies[(policy['adkim'], policy['aspf'], policy['p'], policy['sp'], policy['pct'])].append((file, (domain, org_name, start, end, policy, results)))
        for policy in sorted(policies.keys()):
            table.append([date, 'adkim={0} aspf={1} p={2} sp={3} pct={4}'.format(*policy)])
            for file, (domain, org_name, start, end, the_policy, results) in policies[policy]:
                field = '{0} ({1}) for {2}'.format(domain, org_name, the_policy['domain'])
                for source_ip, count, policy_evaluated, header_from, auth_results in results:
                    is_own = (source_ip in own_ips)
                    table.append([None,
                                  field,
                                  count,
                                  (source_ip, 'green' if is_own else 'yellow'),
                                  (policy_evaluated['disposition'], 'green' if (policy_evaluated['disposition'] == 'none') == (is_own or policy[2] == 'none') else 'red'),
                                  (policy_evaluated['dkim'], 'green' if (policy_evaluated['dkim'] == 'pass') == is_own else 'red'),
                                  (policy_evaluated['spf'], 'green' if (policy_evaluated['spf'] == 'pass') == is_own else 'red'),
                                  header_from,
                                  format_result(auth_results.get('dkim', None)),
                                  format_result(auth_results.get('spf', None))])
                    field = None
                if field is not None:
                    table.append([None, field])
        table.append(None)
    table.append(None)
    return table


if 'OWN_IPS' not in globals():
    print("Please first set OWN_IPS to your own set of IP addresses before running this script!")
    sys.exit()

files = scan('.')
dmarc_table = prepare_table(files, own_ips=OWN_IPS)
print(table.format_table(dmarc_table, mode='pretty_text'))
