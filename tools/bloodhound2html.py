import json
import sys
import copy
import os
from datetime import datetime

def html(body):
    style = '''<style type="text/css">tbody th {
    border: 1px solid #000;
}
tbody td {
    border: 1px solid #ababab;
    border-spacing: 0px;
    padding: 4px;
    border-collapse: collapse;
    white-space:pre;
}
body {
    font-family: verdana;
}
table {
    font-size: 13px;
    border-collapse: collapse;
    width: 100%;
}
tbody tr:nth-child(odd) td {
    background-color: #eee;
}
tbody tr:hover td {
    background-color: lightblue;
}
thead td {
    font-size: 19px;
    font-weight: bold;
    padding: 10px 0px;
}
</style>'''
    html_content = f'''<html>
<head><meta charset="UTF-8">
{style}</head><body>
{body}
</body></html
'''
    return html_content

def get_value(data, key):
    if key in data:
        return data['key']
    return None

def html_table(data, title=''):
    body = ''
    for d in data:
        body += '<tr>\n'
        for content in d:
            body += '<td>'
            for line in content.split('\n'):
                
                if 'Group:' in line:
                    name = line.split('Group:')[1].strip()
                    cn = name.split('@')[0]
                    body += f'Group: <a href="./domain_users_by_group.html#{cn}" title="{name}">{name}</a>\n'
                elif 'Computer:' in line:
                    name = line.split('Computer:')[1].strip()
                    cn = name.split('@')[0]
                    body += f'Computer: <a href="./domain_computers.html#{cn}" title="{name}">{name}</a>\n'
                else:
                    # 使用者
                    body += '%s\n' % line
            body += '</td>\n'
        body += '</tr>\n'

    template = f'''<table><thead><tr><td colspan="7" id="{title}">{title}</td></tr></thead>
  <tbody>{body}</tbody></table>
'''
    return template

def tocsv(data):
    ret = ''
    for d in data:
        for c in d:
            ret += '"%s",' % c
        ret += '\n'
    return ret

def make_dict_by_objectidentifier(data, obj=dict(), objecttype=''):
    for d in data['data']:
        sid = d['ObjectIdentifier']
        update = True

        # 如果資料已經存在，並且新的資料數量比較少，就不更新
        if sid in obj:
            print('%s already exists' % sid)
            if str(len(obj[sid])) > str(len(d)):
                update = False
        
        if update:
            obj[sid] = d
            obj[sid]['ObjectType'] = objecttype
    return obj

def parse_user(jdata, all_obj=dict()):
    ret = [['Name', 'CN', 'Domain', 'Description', 'SID', 'Aces (hidden default admin groups)', 'Created on', 'pwdlastset']]

    try:
        jdata['data']
    except:
        print(jdata)
    for data in jdata['data']:
        data['ObjectType'] = 'User'
        AllowedToDelegate = ','.join([str(x) for x in data['AllowedToDelegate']])
        HasSIDHistory = ','.join(data['HasSIDHistory'])
        try:
            SPNTargets = ','.join(str(x) for x in data['SPNTargets'])
        except:
            print(data['SPNTargets'])
            sys.exit(0)

        Aces = ''
        for ace in data['Aces']:
            if ace['PrincipalSID'] in all_obj:
                SID = ace['PrincipalSID']
                ace['PrincipalSID'] = all_obj[SID]['Properties']['name']
                # print(all_obj[ace['PrincipalSID']])
        # hidden admin groups
        hidden_groups = ['DOMAIN ADMINS', 'ACCOUNT OPERATORS', 'DOMAIN ADMINS', 'KEY ADMINS', 'ENTERPRISE KEY ADMINS', 'ENTERPRISE ADMINS','ADMINISTRATORS']
        for ace in data['Aces']:
            if ace['PrincipalSID'].split('@')[0] not in hidden_groups:
                Aces = str(ace) + '\n'
            #'\n'.join([if str(x).split('@')[0] in hidden_groups  for x in data['Aces']])
        Aces = Aces[:-1]

        ObjectIdentifier = data['ObjectIdentifier']
        IsDeleted = str(data['IsDeleted'])
        IsACLProtected = ''
        if 'IsACLProtected' in IsACLProtected:
            IsACLProtected = str(data['IsACLProtected'])

        Properties = data['Properties']
        
        domain = Properties['domain']
        name = Properties['name']
        if 'distinguishedname' in Properties:
            distinguishedname = Properties['distinguishedname']
            cn = distinguishedname.split('CN=')[1].split(',')[0] if distinguishedname != 'None' else 'None'
        highvalue = str(Properties.get('highvalue', ''))
        domainsid = str(Properties.get('domainsid', ''))
        description = str(Properties.get('description', ''))
        whencreated = datetime_str(Properties.get('whencreated', 0))
        sensitive = str(Properties.get('sensitive', ''))
        dontreqpreauth = str(Properties.get('dontreqpreauth', ''))
        passwordnotreqd = str(Properties.get('passwordnotreqd', ''))
        unconstraineddelegation = str(Properties.get('unconstraineddelegation', ''))
        pwdneverexpires = str(Properties.get('pwdneverexpires', ''))
        enabled = str(Properties.get('enabled', ''))
        trustedtoauth = str(Properties.get('trustedtoauth', ''))
        lastlogon = str(Properties.get('lastlogon', ''))
        lastlogontimestamp = str(Properties.get('lastlogontimestamp', ''))
        pwdlastset = datetime_str(Properties.get('pwdlastset', 0))
        serviceprincipalnames = ','.join(Properties.get('serviceprincipalnames', []))
        hasspn = str(Properties.get('hasspn', ''))
        displayname = str(Properties.get('displayname', ''))
        email = str(Properties.get('email', ''))
        title = str(Properties.get('title', ''))
        homedirectory = str(Properties.get('homedirectory', ''))
        userpassword = str(Properties.get('userpassword', ''))
        unixpassword = str(Properties.get('unixpassword', ''))
        unicodepassword = str(Properties.get('unicodepassword', ''))
        sfupassword = str(Properties.get('sfupassword', ''))
        admincount = str(Properties.get('admincount', ''))
        sidhistory = ','.join(Properties.get('sidhistory', []))


        ret.append([name, cn, domain, description, ObjectIdentifier, Aces, whencreated, pwdlastset])

    return ret

def parse_groups(jdata, all_obj=dict()):
    ret = [['domain', 'CN', 'description', 'Aces', 'Created on', 'SID', 'highvalue', 'Members']]

    for data in jdata['data']:
        data['ObjectType'] = 'Group'
        Members = ','.join(str(data['Members']))

        for ace in data['Aces']:
            if ace['PrincipalSID'] in all_obj:
                SID = ace['PrincipalSID']
                ace['PrincipalSID'] = all_obj[SID]['Properties']['name']
                # print(all_obj[ace['PrincipalSID']])
        Aces = '\n'.join([str(x) for x in data['Aces']])


        ObjectIdentifier = data['ObjectIdentifier']

        IsDeleted = str(data['IsDeleted'])

        IsACLProtected = ''
        if 'IsACLProtected' in data:
            IsACLProtected = str(data['IsACLProtected'])

        Properties = data['Properties']
        domain = Properties['domain']
        name = Properties['name']
        domainsid = Properties.get('domainsid', '')
        distinguishedname = Properties.get('distinguishedname', 'None')
        highvalue = str(Properties.get('highvalue', 'None'))
        description = str(Properties.get('description', 'None'))
        whencreated = datetime_str(Properties.get('whencreated', 0))
        admincount = str(Properties.get('admincount', 'None'))

        CN = distinguishedname.split('CN=')[1].split(',')[0] if distinguishedname != 'None' else 'None'
        SID = ObjectIdentifier.split('-')[-1]

        Members = ''
        if highvalue == 'True':
            for member in data['Members']:
                ObjectType = member['ObjectType']
                _ObjectIdentifier = member['ObjectIdentifier']

                if _ObjectIdentifier in all_obj:
                    Members += '%s: %s' % (ObjectType, all_obj[_ObjectIdentifier]['Properties']['name']) + '\n'
                else:
                    Members += '%s: %s' % (ObjectType, _ObjectIdentifier) + '\n'
                        

        ret.append([domain, CN, description, Aces, whencreated, SID, highvalue, Members])
    return ret

def parser_computers(jdata, all_obj=dict()):
    ret = [['Name', 'Domain', 'SAM', 'Description', 'ACES (hidden default admin groups)', 'Local Admins', 'unconstraineddelegation']]
    computers = dict()
    
    for data in jdata['data']:
        data['ObjectType'] = 'Computer'
        PrimaryGroupSID = data.get('PrimaryGroupSID', '')
        AllowedToDelegate = ','.join(data.get('AllowedToDelegate', ''))
        AllowedToAct = ','.join(data.get('AllowedToAct', ''))
        HasSIDHistory = ','.join(data.get('HasSIDHistory', ''))
        DumpSMSAPassword = ','.join(data.get('DumpSMSAPassword', ''))
        Sessions = str(data.get('Sessions', ''))
        PrivilegedSessions = str(data.get('PrivilegedSessions', ''))
        RegistrySessions = str(data.get('RegistrySessions', ''))

        # LocalAdmins
        localadmin = ''
        if 'LocalAdmins' in data:
            for admin in data['LocalAdmins']['Results']:
                if admin['ObjectIdentifier'] in all_obj:
                    localadmin += admin['ObjectType'] + ': ' + all_obj[admin['ObjectIdentifier']]['Properties']['name'] + '\n'
                else:
                    localadmin += admin['ObjectType'] + ': ' + admin['ObjectIdentifier'] + '\n'
        RemoteDesktopUsers = ''
        if 'RemoteDesktopUsers' in data: 
            RemoteDesktopUsers = str(data['RemoteDesktopUsers'])
        
        DcomUsers = ''
        if 'DcomUsers' in data:
            DcomUsers = str(data['DcomUsers'])

        PSRemoteUsers = ''
        if 'PSRemoteUsers' in data:
            PSRemoteUsers = str(data['PSRemoteUsers'])
        Status = str(data['Status'])

        # Aces
        Aces = ''
        for ace in data['Aces']:
            if ace['PrincipalSID'] in all_obj:
                SID = ace['PrincipalSID']
                ace['PrincipalSID'] = all_obj[SID]['Properties']['name']

                # print(all_obj[ace['PrincipalSID']])
        # hidden admin groups
        hidden_groups = ['DOMAIN ADMINS', 'ACCOUNT OPERATORS', 'DOMAIN ADMINS', 'KEY ADMINS', 'ENTERPRISE KEY ADMINS', 'ENTERPRISE ADMINS','ADMINISTRATORS']
        for ace in data['Aces']:
            if ace['PrincipalSID'].split('@')[0] not in hidden_groups:
                Aces = str(ace) + '\n'
            #'\n'.join([if str(x).split('@')[0] in hidden_groups  for x in data['Aces']])
        Aces = Aces[:-1]

        ObjectIdentifier = data['ObjectIdentifier']
        
        # Proterties
        Properties = data['Properties']
        domain = Properties['domain']
        name = Properties['name']
        distinguishedname = Properties['distinguishedname']
        domainsid = Properties['domainsid']
        highvalue = str(Properties['highvalue']) if 'highvalue' in Properties else None
        samaccountname = Properties['samaccountname']
        haslaps = ''

        haslaps = str(Properties.get('haslaps', ''))
        description = str(Properties.get('description', ''))
        whencreated = datetime_str(Properties.get('whencreated', 0))
        enabled = str(Properties.get('enabled', ''))
        unconstraineddelegation = str(Properties.get('unconstraineddelegation', ''))
        trustedtoauth = str(Properties.get('trustedtoauth', ''))
        lastlogon = str(Properties.get('lastlogon', ''))
        lastlogontimestamp = str(Properties.get('lastlogontimestamp', ''))
        pwdlastset = datetime_str(Properties.get('pwdlastset', 0))
        serviceprincipalnames = ','.join(Properties.get('serviceprincipalnames', []))
        operatingsystem = str(Properties.get('operatingsystem', ''))
        sidhistory = ','.join(Properties.get('sidhistory', []))
        
        ret.append([name, domain, samaccountname, description, Aces, localadmin, unconstraineddelegation])



    return ret

def parser_gpos(jdata, all_obj=dict()):
    ret = [['Name', 'Domain', 'Aces', 'highvalue', 'whencreated', 'gpcpath']]
    computers = dict()
    Properties = ''
    domain = ''
    name = ''
    distinguishedname = ''
    domainsid = ''
    highvalue = ''
    description = ''
    whencreated = ''
    gpcpath = ''
    for data in jdata['data']:
        # Properties
        Properties = data['Properties']
        domain = Properties.get('domain', '')
        name = Properties.get('name', '')
        distinguishedname = Properties.get('distinguishedname', '')
        domainsid = Properties.get('domainsid', '')
        highvalue = str(Properties.get('highvalue', ''))
        description = str(Properties.get('description', ''))
        whencreated = datetime_str(Properties.get('whencreated', ''))
        gpcpath = str(Properties.get('gpcpath', ''))
    
        # Aces
        for ace in data['Aces']:
            if ace['PrincipalSID'] in all_obj:
                SID = ace['PrincipalSID']
                ace['PrincipalSID'] = all_obj[SID]['Properties']['name']
        Aces = '\n'.join([str(x) for x in data['Aces']])

        ObjectIdentifier = data['ObjectIdentifier']
        IsDeleted = str(data['IsDeleted'])
        IsACLProtected = str(data['IsACLProtected'])
        ret.append([name, domain, Aces, highvalue, whencreated, gpcpath])
    return ret

def parser_domains(jdata, all_obj=dict()):
    ret = [['Name', 'Domain', 'DomainSID', 'Aces', 'Trusts', 'highvalue']]
    computers = dict()

    for data in jdata['data']:
        GPOChanges = data.get('GPOChanges', {})
        LocalAdmins = '\n'.join(GPOChanges.get('LocalAdmins', []))
        RemoteDesktopUsers = '\n'.join(GPOChanges.get('RemoteDesktopUsers', []))
        DcomUsers = '\n'.join(GPOChanges.get('DcomUsers', []))
        PSRemoteUsers = '\n'.join(GPOChanges.get('PSRemoteUsers', []))
        AffectedComputers = str(GPOChanges.get('AffectedComputers', ''))
        Properties = data.get('Properties', {})
        domain = Properties.get('domain', '')
        name = Properties.get('name', '')
        distinguishedname = Properties.get('distinguishedname', '')
        domainsid = Properties.get('domainsid', '')
        highvalue = str(Properties.get('highvalue', ''))
        description = str(Properties.get('description', ''))
        whencreated = datetime_str(Properties.get('whencreated', ''))
        functionallevel = str(Properties.get('functionallevel', ''))

        ChildObjects = ''
        for childobject in data['ChildObjects']:
            ChildObjects += '%s: %s\n' % (childobject['ObjectType'], childobject['ObjectIdentifier'])

        Trusts = ''
        for trust in data['Trusts']:
            for key in trust:
                Trusts += '%s: %s\n' % (key, str(trust[key]))
            Trusts += '--\n'
        Links = ''
        for link in data['Links']:
            for key in link:
                Links += '%s: %s\n' % (key, str(link[key]))

        # Aces
        for ace in data['Aces']:
            if ace['PrincipalSID'] in all_obj:
                SID = ace['PrincipalSID']
                ace['PrincipalSID'] = all_obj[SID]['Properties']['name']
        Aces = '\n'.join([str(x) for x in data['Aces']])

        ObjectIdentifier = data.get('ObjectIdentifier', '')
        IsDeleted = str(data.get('IsDeleted', ''))
        IsACLProtected = str(data.get('IsACLProtected', ''))
        ret.append([name, domain, ObjectIdentifier, Aces, Trusts, highvalue])
    return ret

def parse_users_by_group(jdata, users_and_groups):
    global user_data
    ret = []
    
    for data in jdata['data']:
        members = dict({'data': []})
        if 'distinguishedname' not in data['Properties']:
            continue
        CN = data['Properties']['distinguishedname'].split('CN=')[1].split(',')[0]

        # 取得 groups 底下的 members
        for m in data['Members']:
            sid = m['ObjectIdentifier']
            try:
                members['data'].append(users_and_groups[sid])
            except KeyError as e:
                members['data'].append(m)
        ret.append([CN, copy.deepcopy(members)])
    return ret

def parse_group_by_groups(jdata, groups):
    global user_data
    ret = []
    
    for data in jdata['data']:
        members = dict({'data': []})
        if 'distinguishedname' not in data['Properties']:
            continue

        CN = data['Properties']['distinguishedname'].split('CN=')[1].split(',')[0]
        for m in data['Members']:
            if m['ObjectType'] == 'Group':
                members['data'].append(groups[m['ObjectIdentifier']])
        ret.append([CN, copy.deepcopy(members)])
    return ret

def parse_user_and_group(users_and_groups):
    ret = [['Name', 'CN', 'Domain', 'Description', 'SID', 'Created on', 'pwdlastset']]

    for data in users_and_groups['data']:
        # print(data)
        SID = str(data['ObjectIdentifier'])
        Properties = data['Properties'] if 'Properties' in data else None

        name = ''
        cn = ''
        domain = ''
        description = ''
        whencreated = ''
        pwdlastset = ''
        if Properties is not None:
            domain = str(Properties['domain'])
            description = str(Properties.get('description', '')) 
            whencreated = datetime_str(Properties.get('whencreated', 0)) 
            pwdlastset = datetime_str(Properties.get('pwdlastset', 0))
            
            if 'distinguishedname' in Properties:
                distinguishedname = Properties['distinguishedname']
                cn = distinguishedname.split('CN=')[1].split(',')[0]
                if data['ObjectType'] == 'Group':
                    cn = 'Group: ' + cn
                elif data['ObjectType'] == 'Computer':
                    cn = 'Computer: ' + cn
            name = Properties.get('name', '')

        ret.append([name, cn, domain, description, SID, whencreated, pwdlastset])
    return ret

def datetime_str(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def convert_from_sid(sid):
    global all_obj
    if sid in all_obj:
        return all_obj[sid]['name']
    else:
        return sid


user_data = dict({'data': []})
bloodhound_data = dict()

all_type = ['users', 'computers', 'domains', 'groups', 'ous', 'gpos', 'containers']
for t in all_type:
    bloodhound_data[t] = dict({'data': []})

folder = sys.argv[1]
for filename in os.listdir(folder):
    for t in all_type:
        if t in filename and filename.endswith('.json'):
            filename_users = os.path.join(folder, filename)
            data = open(filename_users, 'rb').read().decode('utf-8-sig')
            _data = json.loads(data)

            # 合併
            for _ in _data['data']:
                bloodhound_data[t]['data'].append(_)      
            break

    '''
    if 'users' in filename:
        filename_users = os.path.join(folder, filename)
        data = open(filename_users, 'rb').read().decode('utf-8-sig')
        _data = json.loads(data)
        for _ in _data['data']:
            user_data['data'].append(_)

    elif 'computers' in filename:
        filename_computers = os.path.join(folder, filename)
    elif 'domains' in filename:
        filename_domains = os.path.join(folder, filename)
    elif 'groups' in filename:
        filename_groups = os.path.join(folder, filename)
    elif 'ous' in filename:
        filename_ous = os.path.join(folder, filename)
    elif 'gpos' in filename:
        filename_gpos = os.path.join(folder, filename)
    elif 'containers' in filename:
        filename_containers = os.path.join(folder, filename)

    '''
'''
all_obj = make_dict_by_objectidentifier(user_data, objecttype='User')
data = open(filename_groups, 'rb').read().decode('utf-8-sig')
group_data = json.loads(data)
all_obj = make_dict_by_objectidentifier(group_data, objecttype='Group')
data = open(filename_computers, 'rb').read().decode('utf-8-sig')
computer_data = json.loads(data)
all_obj = make_dict_by_objectidentifier(computer_data, objecttype='Computer')       
'''


all_obj = make_dict_by_objectidentifier(bloodhound_data['users'], objecttype='User')
all_obj = make_dict_by_objectidentifier(bloodhound_data['groups'], objecttype='Group')
all_obj = make_dict_by_objectidentifier(bloodhound_data['computers'], objecttype='Computer')
all_obj = make_dict_by_objectidentifier(bloodhound_data['domains'], objecttype='domains')
all_obj = make_dict_by_objectidentifier(bloodhound_data['gpos'], objecttype='gpos')
# Users
ret = parse_user(bloodhound_data['users'], all_obj)

with open('domain_user.html', 'w') as f:
    f.write(html(html_table(ret)))

with open('domain_user.csv', 'w', encoding='utf-8-sig') as f:
    f.write(tocsv(ret))

# Groups
ret = parse_groups(bloodhound_data['groups'], all_obj)
with open('domain_groups.html', 'w') as f:
    f.write(html(html_table(ret, 'cn_Domain_groups')))

with open('domain_groups.csv', 'w', encoding='utf-8-sig') as f:
    f.write(tocsv(ret))

# Computers
ret = parser_computers(bloodhound_data['computers'], all_obj)
with open('domain_computers.html', 'w') as f:
    f.write(html(html_table(ret)))

# Users by group
ret = parse_users_by_group(bloodhound_data['groups'], all_obj)
tables = ''
for groupname_and_groupinfo in ret:
    groupname = groupname_and_groupinfo[0]
    groupinfo = groupname_and_groupinfo[1]
    ret = parse_user_and_group(groupinfo)
    tables += html_table(ret, groupname)

with open('domain_users_by_group.html', 'w') as f:
    f.write(html(tables))

# Gpos
ret = parser_gpos(bloodhound_data['gpos'])
with open('domain_gpos.html', 'w') as f:
    f.write(html(html_table(ret)))

# domains
ret = parser_domains(bloodhound_data['domains'])
with open('domain_domains.html', 'w') as f:
    f.write(html(html_table(ret)))

with open('all_obj.json', 'w') as f:
    f.write(json.dumps(all_obj, indent=2))

'''
ret = parse_group_by_groups(group_data, groups)

tables = ''
for groups_by_users in ret:
    a = parse_groups(groups_by_users[1])[0]
    tables += html_table(a, groups_by_users[0])

with open('domain_group_by_groups.html', 'w') as f:
    f.write(html(tables))
'''
