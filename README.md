<h1 align="center">FCaptcha Solver</h1>
<p align="center">
  <img src="https://i.imgur.com/AMdXVo0.png" alt="Demo Screenshot" style="display: block; margin: 0 auto;" />
</p>

A full reversal for a very fun captcha from a Lab that does Arkose, including fully working API & all JS encryption/decryption logic converted to GO.

## 📫 Contact

- 🟣 Telegram: [@mr_alejandroo](https://t.me/mr_alejandroo)  
- 🟣 Discord: `mr.alejandroo`


## 🧵 Background

I know I might be a bit late to the scene... but with other solvers already leaked, and since I no longer use mine, I'm releasing it publicly for the community. How is this one better?

> 🎯 **The advantage?** Everything (except `dapib`) runs natively in **Go**.  
> 🚫 No JavaScript VM required for encryption — smoother, faster, cleaner.  
> 🔐 TLS Client using bogdannfinn  
> 📦 Many existing presets  

It should hopefully be used as a foundation and reference when making your own solver and not as a tool in your production. Only suppressed sites will be solved currently.


‎ 
## ⚠️ Notes
> 🔐 **AI is not included** for solving image challenges.
> 
> 🧪 It's outdated by a couple minor versions, not that it impacts anything yet.
> 
> 🕵️ Only a single chrome fingerprint is included, that way you have to actually work to collect some before running it. This is my skid security system.



‎ 

## 🚀 Quickstart

```bash
git clone https://github.com/mr-alejandroo/fncaptcha-solver
cd fncaptcha-solver
go run .
```
‎ 

‎ 
## 📡 API Endpoints
 
### 📥 `POST /createTask`

```jsonc
{
        "preset": "snapchat_register", // all presets are in /utils/presets.go
        "blob": "", // optional if BlobRequired is true
        "proxy": "http://user:pass@host:port",
        "platform": "chrome",
        "hardcoded": false // recommended for debugging (will use custom_pc_bda.go / custom_ios_bda.go)
}
```
Response - 200:
```json
{
    "success": true,
    "task_id": "fca60cf7e5d24e72926f4c0ffda227c6"
}
```
‎ 




‎ 
### 📥 `POST /getTask`
```json
{
     "task_id": "fca60cf7e5d24e72926f4c0ffda227c6"
}
```
Response - 200:
```json
{
    "status": "completed",
    "success": true,
    "time": 3.81,
    "token": "664184635c95ddf05.1259418705|r=eu-west-1|meta=3|metabgclr=transparent|metaiconclr=%23757575|guitextcolor=%23000000|lang=en|pk=EA4B65CB-594A-438E-B4B5-D0DBA28C9334|at=40|sup=1|rid=8|ag=101|cdn_url=https%3A%2F%2Fsnap-api.arkoselabs.com%2Fcdn%2Ffc|surl=https%3A%2F%2Fsnap-api.arkoselabs.com|smurl=https%3A%2F%2Fsnap-api.arkoselabs.com%2Fcdn%2Ffc%2Fassets%2Fstyle-manager"
}
```
‎ 



‎ 

## 📄 License & Terms of Usage

This project is open-source under the [MIT License](./LICENSE).  
It's also intended for educational and research purposes only.
Use at your own risk. The author does not condone or support misuse, abuse, or violation of any service's terms of use.

## Credits
- Madokax - his repos initially inspired me to create my own solver and AI modules
- [@Fredrik-Rafn](https://github.com/Fredrik-Rafn) — for help with improving FPs and motivation to continuously unflag.  
- [@AzureFlow](https://github.com/AzureFlow) — for his amazing FC fingerprint docs, which you can read [here](https://azureflow.github.io/arkose-fp-docs/arkose_re_docs.html)
