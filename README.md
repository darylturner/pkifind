Tool to search through Vault PKI backend by subject name and report revocation status.

```
> pkifind -help
Usage of pkifind:
  -address string
        override VAULT_ADDR environment variable
  -ca string
        vault pki mount to search through (default "pki")
  -search string
        common name search term
  -token string
        override VAULT_TOKEN environment variable
> ./pkifind -ca pki-test -search "mr-test"
[
    {
        "common_name": "mr-test-1.client-test.vpn",
        "valid_from": "2017-04-05T08:31:42Z",
        "valid_until": "2017-04-06T08:32:12Z",
        "serial": "11-df-ff-b2-e2-d3-1f-07-14-65-ea-dc-7f-75-ad-43-bd-bd-4a-aa",
        "revoked": true
      
    },
    {
        "common_name": "mr-test-1.client-test.vpn",
        "valid_from": "2017-04-05T15:27:13Z",
        "valid_until": "2017-04-06T15:27:43Z",
        "serial": "22-88-7f-28-b1-f1-a4-a4-ac-25-98-c2-43-b7-f6-d7-3d-8b-e5-b3",
        "revoked": true
      
    },
    {
        "common_name": "mr-test-1.client-test.vpn",
        "valid_from": "2017-04-05T15:42:17Z",
        "valid_until": "2017-04-06T15:42:47Z",
        "serial": "57-e7-eb-a8-87-4e-02-5e-4b-01-6e-15-d9-84-62-02-17-de-20-93",
        "revoked": false
      
    }
]
```
