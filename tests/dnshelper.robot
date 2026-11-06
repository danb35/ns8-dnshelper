*** Settings ***
Library    SSHLibrary

*** Variables ***
# Never a real token: nothing here talks to a DNS provider, except the
# screenshot case, which talks to a throwaway PowerDNS on the test node itself.
${TOKEN}    ci-not-a-real-token-0123456789
${ADMIN_USER}    admin
${ADMIN_PASSWORD}    Nethesis,1234
${UI_ZONE}    ui.example.test
${PDNS_IMAGE}    docker.io/powerdns/pdns-auth-49:4.9.17
${PDNS_API}    http://127.0.0.1:18081
${PDNS_KEY}    ci-ui-not-a-real-key

*** Keywords ***
Run action
    [Arguments]    ${action}    ${data}={}
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/${action} --data '${data}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0    ${action} failed: ${output}
    ${parsed} =    Evaluate    json.loads(r'''${output}''' or '{}')    modules=json
    RETURN    ${parsed}

Start a PowerDNS server with a zone
    # PowerDNS on the node's loopback, so that the Records page shows a real zone
    ${rc} =    Execute Command
    ...    podman run -d --name dnshelper-ui-pdns -p 127.0.0.1:18081:8081 -e PDNS_AUTH_API_KEY=${PDNS_KEY} ${PDNS_IMAGE}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    ${rc} =    Execute Command
    ...    for i in $(seq 90); do curl -fsS -o /dev/null -H 'X-API-Key: ${PDNS_KEY}' ${PDNS_API}/api/v1/servers/localhost \&\& exit 0; sleep 1; done; exit 1
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0    PowerDNS did not start
    ${rc} =    Execute Command
    ...    curl -fsS -o /dev/null -H 'X-API-Key: ${PDNS_KEY}' -X POST -d '{"name":"${UI_ZONE}.","kind":"Native","nameservers":["ns1.${UI_ZONE}."],"soa_edit_api":"DEFAULT"}' ${PDNS_API}/api/v1/servers/localhost/zones
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0

Remove the screenshot zone
    Run Keyword And Ignore Error    Run action    remove-zone    {"zone":"${UI_ZONE}"}
    Run Keyword And Ignore Error    Run action    remove-credential    {"id":"${ui_credential}"}
    Execute Command    podman rm -f dnshelper-ui-pdns

Login to cluster-admin
    New Page    https://${NODE_ADDR}/cluster-admin/
    Fill Text    text="Username"    ${ADMIN_USER}
    Click    button >> text="Continue"
    Fill Text    text="Password"    ${ADMIN_PASSWORD}
    Click    button >> text="Log in"
    Wait For Elements State    css=#main-content    visible    timeout=10s

Open page
    [Arguments]    ${page}    ${heading}    ${shot}
    Go To    https://${NODE_ADDR}/cluster-admin/#/apps/${module_id}?page=${page}
    Wait For Elements State    iframe >>> h2 >> text="${heading}"    visible    timeout=30s
    Sleep    5s
    Take Screenshot    filename=${OUTPUT DIR}/browser/screenshot/${shot}.png

Open a dialog
    [Arguments]    ${text}    ${shot}
    Wait For Elements State    iframe >>> text=${text}    visible    timeout=30s
    Sleep    2s
    Take Screenshot    filename=${OUTPUT DIR}/browser/screenshot/${shot}.png

*** Test Cases ***
Check if dnshelper is installed correctly
    ${output}  ${rc} =    Execute Command    add-module ${IMAGE_URL} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    &{output} =    Evaluate    ${output}
    Set Suite Variable    ${module_id}    ${output.module_id}

Check if dnshelper can be configured
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/configure-module --data '{}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0

Check if providers are listed
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/list-providers --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    Should Contain    ${output}    cloudflare

Check if a credential and a zone can be added
    ${output}  ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/add-credential --data '{"name":"CI","provider":"cloudflare","fields":{"api_token":"${TOKEN}"}}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    ${result} =    Evaluate    json.loads('''${output}''')    modules=json
    Set Suite Variable    ${credential_id}    ${result}[id]
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/add-zone --data '{"zone":"ci.example.test","credential":"${credential_id}"}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0

Check if the zone is found by a host name inside it
    ${output}  ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/has-zone --data '{"name":"mail.ci.example.test"}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    ${result} =    Evaluate    json.loads('''${output}''')    modules=json
    Should Be Equal    ${result}[zone]    ci.example.test

Check if the configuration reads back without secrets
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/get-configuration --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    Should Not Contain    ${output}    ${TOKEN}
    ${config} =    Evaluate    json.loads('''${output}''')    modules=json
    Should Be Equal    ${config}[zones][0][zone]    ci.example.test

Check if the credential file is private
    ${output} =    Execute Command    stat -c %a /home/${module_id}/.config/state/credentials/${credential_id}.json
    Should Be Equal    ${output}    600

Check if a credential in use cannot be removed
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/remove-credential --data '{"id":"${credential_id}"}'
    ...    return_rc=True  return_stdout=False  return_stderr=False
    Should Not Be Equal As Integers    ${rc}  0

Check if the zone and credential can be removed
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/remove-zone --data '{"zone":"ci.example.test"}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/remove-credential --data '{"id":"${credential_id}"}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0

Check if the service provider is registered
    ${output}  ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/list-service-providers --data '{"service":"dnshelper"}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    Should Contain    ${output}    ${module_id}

Check if the policy can be set and read back
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/set-policy --data '{"rules":[{"caller":"module/mail1","zone":"ci.example.test","access":"write","names":["_domainkey","*._domainkey"],"types":["TXT"]}]}'
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    ${output}  ${rc} =    Execute Command    api-cli run module/${module_id}/get-policy --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}  0
    ${policy} =    Evaluate    json.loads('''${output}''')    modules=json
    Should Be Equal    ${policy}[rules][0][caller]    module/mail1

Check if an invalid policy is rejected
    ${rc} =    Execute Command
    ...    api-cli run module/${module_id}/set-policy --data '{"rules":[{"caller":"module/mail1","zone":"ci.example.test","access":"write","names":["a b"]}]}'
    ...    return_rc=True  return_stdout=False  return_stderr=False
    Should Not Be Equal As Integers    ${rc}  0

Check if the policy file is private
    ${output} =    Execute Command    stat -c %a /home/${module_id}/.config/state/policy.json
    Should Be Equal    ${output}    600

Check if the state to back up is complete
    ${rc} =    Execute Command    runagent -m ${module_id} module-dump-state
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
    FOR    ${path}    IN    zones.json    policy.json    credentials    settings.json    snapshots
        ${rc} =    Execute Command    test -e /home/${module_id}/.config/state/${path}
        ...    return_rc=True  return_stdout=False
        Should Be Equal As Integers    ${rc}  0
    END

Take screenshots of the pages
    [Tags]    ui
    [Setup]    Set Test Variable    ${ui_credential}    ${EMPTY}
    Start a PowerDNS server with a zone
    ${cred} =    Run action    add-credential
    ...    {"name":"PowerDNS (CI)","provider":"powerdns","fields":{"api_url":"${PDNS_API}","api_key":"${PDNS_KEY}"}}
    Set Test Variable    ${ui_credential}    ${cred}[id]
    Run action    add-zone    {"zone":"${UI_ZONE}","credential":"${ui_credential}"}
    Run action    create-snapshot    {"zone":"${UI_ZONE}","label":"Before the mail setup"}
    Run action    append-records    {"zone":"${UI_ZONE}","records":[{"name":"www","type":"A","data":"192.0.2.10"},{"name":"mail","type":"A","data":"192.0.2.25"},{"name":"@","type":"MX","data":"10 mail.${UI_ZONE}."},{"name":"@","type":"TXT","data":"v=spf1 mx -all"},{"name":"_dmarc","type":"TXT","data":"v=DMARC1; p=quarantine"},{"name":"_autodiscover._tcp","type":"SRV","data":"0 0 443 mail.${UI_ZONE}."}]}
    Run action    apply-changes    {"zone":"${UI_ZONE}","remove":[{"name":"www","type":"A","data":"192.0.2.10"}],"add":[{"name":"www","type":"CNAME","data":"web.example.net."}]}
    Import Library    Browser
    New Browser    chromium    headless=True
    New Context    ignoreHTTPSErrors=True    viewport={'width': 1440, 'height': 900}
    Login to cluster-admin
    Open page    status    Status    1._Status
    Open page    zones    Zones    2._Zones
    Open page    records&zone=${UI_ZONE}    Records    3._Records
    # the MX row: its value is the only one starting "10 mail."
    Click    iframe >>> tr:has-text("10 mail.${UI_ZONE}.") >> css=.bx--overflow-menu
    Click    iframe >>> .bx--overflow-menu-options >> text="Edit"
    Open a dialog    "Edit a record of ${UI_ZONE}"    4._Edit_an_MX_record
    Keyboard Key    press    Escape
    Click    iframe >>> button >> text="Snapshots"
    Open a dialog    "Snapshots of ${UI_ZONE}"    5._Snapshots
    # the oldest snapshot, taken by hand before the records were added
    Click    iframe >>> button >> text="Compare and revert" >> nth=-1
    Open a dialog    "Remove from the zone"    6._Compare_with_a_snapshot
    Keyboard Key    press    Escape
    Open page    access    Access    7._Access
    Open page    settings    Settings    8._Settings
    Open page    about    About    9._About
    Close Browser
    [Teardown]    Remove the screenshot zone

Check if dnshelper is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
