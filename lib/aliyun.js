// This function runs on each request to https://signin.aliyun.com/saml-role/sso and https://*.aliyun.com/entrance?Action=V2AssumeRoleWithSaml 
function saml2aliyun(details) {
    let SamlPayload = "";
    let TargetRole = "";
    let SamlProvider = "";
    console.log("detected aliyun saml login, url:", details.url);
    if (details.url == "https://signin.aliyun.com/saml-role/sso") { //signin.aliyun.com endpoint is suit for one office365 application map to one account and role
        SamlPayload = details.requestBody.formData.SAMLResponse[0]
        samlXmlDoc = decodeURIComponent(
            unescape(atob(SamlPayload))
        );
        parser = new XMLParser(options);
        jsObj = parser.parse(samlXmlDoc);
        attributes = jsObj["Response"].Assertion.AttributeStatement.Attribute;
        for (let i in attributes) {
            if (attributes[i].__Name == "https://www.aliyun.com/SAML-Role/Attributes/Role") {
                Roles = attributes[i].AttributeValue["#text"];
            }
        }
        TargetRole = Roles.split(",")[0];
        SamlProvider = Roles.split(",")[1];
    } else {  //for one office365 application with multiple aliyun account and roles ,will send request to url https://*.aliyun.com/entrance?Action=V2AssumeRoleWithSaml 
        let payload = JSON.parse(details.requestBody.formData.RequestParams[0]);
        SamlPayload = payload.SAMLResponse;
        TargetRole = payload.TargetRoleAndProvider.split(",")[0];
        SamlProvider = payload.TargetRoleAndProvider.split(",")[1];
    }
    let accountid = TargetRole.split(":")[3];
    let rolename = TargetRole.split(":")[4].split("/")[1];
    let prefix = accountid + '-' + rolename
    script_text = `
aliyun configure set --profile fake --mode AK --region cn-hangzhou --access-key-id abc --access-key-secret abc
echo "${SamlPayload}" >${prefix}-saml.log
aliyun sts AssumeRoleWithSAML --DurationSeconds 7200 --RoleArn ${TargetRole} --SAMLProviderArn ${SamlProvider} --SAMLAssertion $(cat ${prefix}-saml.log) --profile fake|jq .Credentials >${prefix}
$ak = (cat ${prefix} |jq -r .AccessKeyId)
$aks = (cat ${prefix}|jq -r .AccessKeySecret)
$st = (cat ${prefix}|jq -r .SecurityToken)
aliyun configure set --profile ${prefix} --mode StsToken --region cn-hangzhou --access-key-id $ak --access-key-secret $aks --sts-token $st
aliyun sts GetCallerIdentity --profile ${prefix}
`
    outputDocAsDownload(script_text);
    return;
}
