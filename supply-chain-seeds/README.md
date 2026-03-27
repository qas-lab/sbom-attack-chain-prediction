### Multi-vulnerability software supply chain attack seeds

This folder contains two JSON files for the SBOM→grype→KG pipeline.

- incidents.json: 8 curated, well-sourced exploit chains (≥2 distinct CVEs) with provenance
- seeds.json: minimal runnable inputs mapping each chain to 1–3 OSS repositories

Selection criteria
- Chain required: two or more distinct CVEs used together, ideally cross-component or staged
- Strong sources: vendor advisories and/or reputable IR (e.g., Volexity, Sansec), NVD links
- OSS analyzability: at least one open-source component or justified open-source surrogate

Included incidents
- AC-SaltStack-2020: CVE-2020-11651 + CVE-2020-11652 (unauth publisher + path traversal) – Salt masters/minions
- AC-GitLab-ExifTool-2021: CVE-2021-22205 + CVE-2021-22204 (GitLab preauth RCE via ExifTool) – GitLab CE + ExifTool
- AC-Zimbra-2022: CVE-2022-27925 + CVE-2022-37042 (upload + auth bypass) – Zimbra OSS modules
- AC-ApacheHttpd-2021: CVE-2021-41773 + CVE-2021-42013 (traversal → RCE) – Apache httpd
- AC-Jenkins-2019: CVE-2019-1003000/1/2 (sandbox escape chain) – Jenkins core + Script Security plugin
- AC-OFBiz-2023: CVE-2023-49070 + CVE-2023-51467 (patch bypass) – Apache OFBiz
- AC-Guacamole-2020: CVE-2020-9497 + CVE-2020-9498 (RDP parsing chain) – Apache Guacamole
- AC-AdobeCommerce-2022: CVE-2022-24086 + CVE-2022-24087 (pre-auth RCE + patch bypass) – Magento 2

Notes on repo mappings
- When the original target is partially closed-source (e.g., GitLab EE, Zimbra builds), we map to the closest OSS code paths used in exploitation (community edition or upstream component). Each seed has a 1–2 sentence rationale plus suspected purls and CVEs to aid labeling.

Promising but excluded (for now)
- Exchange ProxyLogon/ProxyShell chains: strong multi-CVE chains but closed-source target; suitable OSS surrogates require more justification per component.
- MOVEit Transfer: primarily single-CVE initial compromise (CVE-2023-34362) in most public chains; doesn’t cleanly meet the “≥2 distinct CVEs” chain criterion for our MVP.

How to use
- Feed seeds.json to the builder. The extra fields are ignored by the script but helpful for manual review and future labeling.

