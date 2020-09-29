/*
Copyright (c) {{current_year}} Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

__author__ = Chris McHenry
*/

var tpt_protocols = {
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IP-ENCAP",
    5: "ST2",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPV6",
    42: "SDRP",
    43: "IPV6-ROUTE",
    44: "IPV6-FRAG",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE",
    54: "NARP",
    55: "MOBILE",
    56: "TLSP",
    57: "SKIP",
    58: "IPV6-ICMP",
    59: "IPV6-NONXT",
    60: "IPV6-OPTS",
    62: "CFTP",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "TTP",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "CARP",
    113: "PGM",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM",
    123: "PTP",
    124: "ISIS",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "Mobility-Header",
    136: "UDPLite",
    137: "MPLS-IN-IP",
    138: "MANET",
    139: "HIP",
    140: "SHIM6",
    141: "WESP",
    142: "ROHC",
    240: "PFSYNC"
}


function processPoliciesForCSV(policiesToProcess) {
    let processedPolices = [];
    let edgeLength = policiesToProcess['cluster_edges'].length;
    for (i = 0; i < edgeLength; i++) {
        let currentEdge = policiesToProcess['cluster_edges'][i];
        let portLength = currentEdge['l4_details'].length;
        for (j = 0; j < portLength; j++) {
            let policy = {
                'Source': policiesToProcess['filters'][currentEdge['src_id']]['name'],
                'Destination': policiesToProcess['filters'][currentEdge['dst_id']]['name'],
                'Action': currentEdge['action'],
                'Priority': currentEdge['priority'],
                'Rank': currentEdge['rank'],
                'Protocol': tpt_protocols[currentEdge['l4_details'][j]['proto']],
                'Port': currentEdge['l4_details'][j]['port'],
                'Confidence': typeof currentEdge['l4_details'][j]['confidence'] === 'undefined' ? null : currentEdge['l4_details'][j]['confidence'],
                'Auto Discovered': typeof currentEdge['l4_details'][j]['user_defined'] === 'undefined' ? true : false,
                'Approved': typeof currentEdge['l4_details'][j]['approved'] === 'undefined' ? false : currentEdge['l4_details'][j]['approved']
            }
            processedPolices.push(policy);
        }
    }
    return processedPolices.sort(comparePolicies);
}

function comparePolicies(a, b) {
    if (a['Rank'] == 'ABSOLUTE' && b['Rank'] != 'ABSOLUTE') return -1;
    if (a['Rank'] != 'ABSOLUTE' && b['Rank'] == 'ABSOLUTE') return 1;
    if (a['Rank'] == 'DEFAULT' && b['Rank'] == 'CATCH_ALL') return -1;
    if (a['Rank'] == 'CATCH_ALL' && b['Rank'] == 'DEFAULT') return 1;
    if (a['Priority'] > b['Priority']) return 1;
    if (a['Priority'] < b['Priority']) return -1;
    if (a['Source'] > b['Source']) return -1;
    if (a['Source'] < b['Source']) return 1;
    if (a['Destination'] > b['Destination']) return -1;
    if (a['Destination'] < b['Destination']) return 1;
    if (a['Port'] > b['Port']) return 1;
    if (a['Port'] < b['Port']) return -1;
    return 0;
}


function downloadObjectAsCsv(exportObj, exportName) {
    json = exportObj
    fields = Object.keys(json[0])
    replacer = function (key, value) {
        return value === null ? '' : value
    }
    csv = json.map(function (row) {
        return fields.map(function (fieldName) {
            return JSON.stringify(row[fieldName], replacer)
        }).join(',')
    })
    csv.unshift(fields.join(',')) // add header column
    csv = csv.join('\r\n');
    let dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(csv);
    let downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", exportName + ".csv");
    document.body.appendChild(downloadAnchorNode); // required for firefox
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}

async function policyCsvExport() {
    let application = null
    await fetch(tpt_applicationRequest)
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            application = data
        })
        .catch(function (err) {
            console.log("Error getting application details.", err);
            alert('Something went wrong!  Please try refreshing the page.');
        });

    fetch(tpt_policyRequest)
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            downloadObjectAsCsv(processPoliciesForCSV(data), `${application['name']}-${application['full_version']}`)
        })
        .catch(function (err) {
            console.log("Error getting application policies.", err);
            alert('Something went wrong!  Please try refreshing the page.');
        });
}

var tpt_url_regex = /https:\/\/.*\/#\/adm\/datasets\/.*\/v.*/
if (tpt_url_regex.test(window.location.href)) {
    let reqHeader = new Headers();
    reqHeader.append('X-CSRF-Token', document.getElementsByTagName("meta")[0].content);

    let initObject = {
        method: 'GET',
        headers: reqHeader,
    };

    var tpt_url = window.location.href.split('/')
    var tpt_fqdn = tpt_url[2]
    var tpt_dataset = tpt_url[6]
    var tpt_version = tpt_url[7].substring(1)

    var tpt_applicationRequest = new Request(`https://${tpt_fqdn}/api/data_sets/${tpt_dataset}.json?version=${tpt_version}`, initObject)
    var tpt_policyRequest = new Request(`https://${tpt_fqdn}/api/data_sets/${tpt_dataset}/cluster_edges/concise.json?include_suggested=true&version=${tpt_version}`, initObject);

    policyCsvExport();
} else {
    alert("Please navigate to a Tetration Application Policy Workspace to use Tetration Pro Tools.")
}