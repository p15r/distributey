# Key Consumer Setup
Currently, HYOK Wrapper only supports Salesforce as a key consumer.

Specs
- Salesforce HYOK format specification: https://help.salesforce.com/articleView?id=security_pe_byok_cache_create.htm&type=5

Step-by-step
1. Get a developer account: https://developer.salesforce.com/signup
2. Configure `My Domain`: https://help.salesforce.com/articleView?id=domain_name_overview.htm&type=5
3. Configure permission for Key Management: https://trailhead.salesforce.com/en/content/learn/modules/spe_admins/spe_admins_set_up
4. Create Tenant Secret: https://help.salesforce.com/articleView?id=security_pe_ui_setup.htm&type=5
5. How to configure HYOK (a.k.a Cache-only key connection): https://help.salesforce.com/articleView?id=security_pe_byok_cache_callout.htm&type=5
6. Configure JWT auth: tbd

Further reading
- Troubleshoot: https://help.salesforce.com/articleView?id=security_pe_byok_cache_troubleshoot.htm&type=53
