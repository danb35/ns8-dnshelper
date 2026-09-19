*** Settings ***
Library    SSHLibrary

*** Variables ***
# Never a real token: nothing here talks to a DNS provider.
${TOKEN}    ci-not-a-real-token-0123456789

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
    FOR    ${path}    IN    zones.json    policy.json    credentials
        ${rc} =    Execute Command    test -e /home/${module_id}/.config/state/${path}
        ...    return_rc=True  return_stdout=False
        Should Be Equal As Integers    ${rc}  0
    END

Check if dnshelper is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True  return_stdout=False
    Should Be Equal As Integers    ${rc}  0
