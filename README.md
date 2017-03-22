# Railsセキュリティチェックリスト

注）本文書は[英語](https://github.com/eliotsykes/rails-security-checklist/blob/master/README.md)から翻訳したものであり、その内容が最新でない場合もあります。最新の情報はオリジナルの英語版を参照してください。（翻訳日: 2017/03/23)

このチェックリストはRailsのセキュリティの注意事項について書いています。そのため、Railsアプリをセキュアにするために必要なほかのこと(OSやミドルウェアのアップロードなど)についてはカバーしていません。

One aim for this document is to turn it into a community resource much like the [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide).

**留意事項** このチェックリストはすべてを網羅していません。また、セキュリティの専門家ではなく、セキュリティに興味があるRails Developerにより書き始められたので、問題がある場合もあるので、気をつけて下さい。

## The Checklist (_in no particular order_)

### コントローラー
- [ ] `ApplicationController`や抽象コントローラーで、セキュリティのコールバックをデフォルトで有効にする
  - [ ] 認証(authentication) (Devise's `authenticate_user!`)
  - [ ] 権限(authorization) (Pundit's `verify_authorized`)
  - [ ] CSRFプロテクション (protect from forgery)

```rb
class MyPageController
  before_action :authenticate_user!

  # 共通処理
end

class MessageController < MyPageController
  # アクション
end

class MessageController < MyPageController
  # アクション
end
```

### ルート

- [ ] `routes.rb`で、認証と権限チェックを実行する。 コントローラーのコールバックと重複するが意図的に重複させている。 (Devise's `authenticate` and `authenticated`) (motivations: defence-in-depth, swiss cheese model).
- [ ] Check all URL endpoints of engines and other Rack apps mounted in `routes.rb` are protected with correct authentication and authorization checks. For sensitive engines/Rack apps favor not leaking they are installed at all by responding with 404 to non-logged in admin users.
- [ ] Check any developer/test-related engines/Rack apps do not expose any URL endpoints in production. They should not even leak (e.g. via 500 HTTP response code) information that they are installed. Ideally don't have their gems installed in production.


### ビュー

- [ ] クライアントに見えてしまうHTMLコメントを避ける。
```
# bad - "View Source"でHTMLコメントは見える
<!-- これはクライアントに送られる -->
<!-- <%= link_to "Admin Site", "https://admin.example.org/login" %> -->

# ok - ERBコメントはサーバー側で削除されるので、クライアントは見えない
<%# これはクライアントに送られない %>
<%#= link_to "Admin Site", "https://admin.example.org/login" %>
```


### URLシークレットトークン

- URLシークレットトークンがヘッダーの `Referer` でサードパーティに漏れるのを緩和する。(例: パスワードリセットURLはCDNやJSをホストしているサードパーティなどに漏れる可能性がある) (https://robots.thoughtbot.com/is-your-site-leaking-password-reset-links)


### ID

- [ ] シーケンシャルなID (`98`, `99`, `100`, ...) の露出を避ける。サービスの使用度合いや[forced browsing attacks](https://www.owasp.org/index.php/Forced_browsing)をアシストしてしまうかもしれない。IDはフォームやAPIといったURL上で確認できてしまう。
- [ ] もしIDをURL上に表示させる場合は、予測しづらいIDであるUUIDや[hashids](http://hashids.org/ruby/)を使うことが好ましい。ファイルの場合は、[Paperclip's URI Obfuscation](https://github.com/thoughtbot/paperclip#uri-obfuscation)のようなテクニックが予測しづらいパスを生成してくれる。


### Random Token Generation
- [ ] **CONTRIBUTOR NEEDED** Use `SecureRandom` or should we favor https://github.com/cryptosphere/sysrandom ?


### Logging

- [ ] Avoid Rails insecure default where it operates a blocklist and logs most request parameters. A safelist would be preferable. Set up the `filter_parameters` config to log no request parameters:

```rb
# File: config/initializers/filter_parameter_logging.rb
Rails.application.config.filter_parameters += [:password]
if Rails.env.production?
  MATCH_ALL_PARAMS_PATTERN = /.+/
  Rails.application.config.filter_parameters += [MATCH_ALL_PARAMS_PATTERN]
end
```

- [ ] ログファイル、サードパーティロギング、エラー、モニタリングサービスで取得されているデータを監査する。センシティブな情報が見つかることに驚くかもしれない。
- [ ] Favor minimal logging.
- [ ] Consider not archiving logs or regularly purging archived logs stored by you and 3rd parties.


### Input Sanitization

- [ ] すべてのユーザ入力をフィルターし、バリデーションする
- [ ] ユーザが入力したファイル名やパスを使って、ファイルシステムから読み込むを行なうコードを避ける。もし、どうしても必要な場合は、ファイル名やパスの厳重なセーフリストを使う。
- [ ] Any routes that redirect to a URL provided in a query string or POST param should operate a safelist of acceptable redirect URLs and/or limit to only redirecting to paths within the app's URL. Do not redirect to any given URL. (https://railsguides.jp/security.html#%E3%83%AA%E3%83%80%E3%82%A4%E3%83%AC%E3%82%AF%E3%83%88)
- [ ] StrongParameter の箇所に型を強制させるようなレイヤーを追加することを考えてみてください。(https://github.com/zendesk/stronger_parameters)
- [ ] すべての ActiveReocrd の attributes をサニタイズすることを考えてみてください。(favoring the secure default of an opt-out sanitizer such as `Loofah::XssFoliate` https://github.com/flavorjones/loofah-activerecord)


### アップロード、ファイル処理

- [ ] あなたのアプリケーションサーバー上でファイルアップロードをハンドリングすることを避ける
- [ ] アップロードされたファイルをサードパーティサービスを使ってウイルスやマルウェアにかかってないかスキャンすることを推奨する
- [ ] Operate a safelist of allowed file uploads
- [ ] imagemagickや他のイメージ処理ソフトウェアをあなた自信のインフラ上で実行するのを避ける


### Email
- [ ] Throttle the amount of emails that can be sent to a single user (e.g. some apps allow multiple password reset emails to be sent without restriction to the same user)
- [ ] ユーザが入力したデータをメールで送ることを避ける。例えば、URLを変更できる場合、他のユーザはそのリンクをクリックして被害を受けるかもしれない。
- [ ] Email security (needs more info)
  - [ ] Use DKIM (https://scotthelme.co.uk/email-security-dkim/)
  - [ ] etc.


### 乱用と詐欺の検出

- [ ] パスワードが変更されたらメールでユーザに通知する | HOWTOs: [Devise](https://github.com/plataformatec/devise/wiki/Notify-users-via-email-when-their-passwords-change)
- [ ] 重要なアカウントに関連するイベントをユーザに通知することを推奨 (e.g. password change, credit card change, customer/technical support phone call made, new payment charge, new email or other contact information added, wrong password entered, 2FA disabled/enabled, other settings changes, login from a never-before used region and/or IP address)
- [ ] 新しいパスワードを暗号化されていないメールで送らない
- [ ] Consider keeping an audit trail of all significant account-related events (e.g. logins, password changes, etc.) that the user can review (and consider sending this as a monthly summary to them)
- [ ] 危険なアクションに制限をかける。例えば、パスワードの総当たり攻撃などが防げる。
- [ ] ユーザ単位、IPアドレス単位などで貴重なデータの作成に制限をかける。 例えば、IPアドレスでにつき、ソーシャルセキュリティ番号を3つまでしか登録できなくする。 [reduce fraudulent credit card applications](https://twitter.com/theroxyd/status/827525528429137920).


### Logins, Registrations
- [ ] Favor multi-factor authentication
- [ ] Favor Yubikey or similar
- [ ] Nudge users towards using multi-factor authentication. Enable as default and/or provide incentives. For example MailChimp give a 10% discount for enabling 2FA.
- [ ] Favor limiting access per IP-address, per device, especially for administrators
- [ ] Require user confirms account (see Devise's confirmable module)
- [ ] Lock account after X failed password attempts (see Devise's lockable module)
- [ ] Timeout logins (see Devise's timeoutable module)
- [ ] Favor mitigating user enumeration (see paranoid mode in Devise and https://www.owasp.org/index.php/Testing_for_user_enumeration_(OWASP-AT-002))


### Passwords
- [ ] Favor stronger password hashing with higher workload (e.g. favor more stretches). At time of implementation, research what the currently recommended password hashing algorithms are.
- [ ] Add calendar reminder to regularly review your current password storage practices and whether to migrate to a different mechanism and/or increase the workload as CPU performance increases over time.
- [ ] Prevent password reuse
- [ ] Enforce strong, long passwords
- [ ] Prevent commonly-used passwords (see Discourse codebase for an example)
- [ ] Proactively notify/prevent/reset users reusing passwords they've had compromised on other services (https://krebsonsecurity.com/2016/06/password-re-user-get-to-get-busy/ - interestingly Netflix apparently uses Scumblr, an open-sourced Rails app, to help with this: http://techblog.netflix.com/2014/08/announcing-scumblr-and-sketchy-search.html)
- [ ] Consider adding a layer of encryption to the stored password hashes (and other hashed secrets) (https://blogs.dropbox.com/tech/2016/09/how-dropbox-securely-stores-your-passwords/)


### Timing Attacks
- [ ] Favor padding/increasing the time it takes to initially login and to report failed password attempts so as to mitigate timing attacks you may be unaware of and to mitigate brute force and user enumeration attempts. See how PayPal shows the "loading..." screen for a good few seconds when you first login (should this always be a fixed set amount of time e.g. 5 seconds and error asking user to try again if it takes longer?)(please correct me on this or add detail as this is an assumption I'm making about the reasons why PayPal do this).
- [ ] Mitigate timing attacks and length leaks on password and other secret checking code https://thisdata.com/blog/timing-attacks-against-string-comparison/
- [ ] Avoid using secret tokens for account lookup (includes API token, password reset token, etc.). Do not query the database using the token, this is vulnerable to timing attacks that can reveal the secret to an attacker. Use an alternative identifier that is not the token for the query (e.g. username, email, `api_locator`).
```rb
# bad - timing attack can reveal actual token
user = User.find_by(token: submitted_token)
authenticated = !user.nil?

# ok
# step 1: find user by an identifier that is *not* the API key, e.g. username, email, api_locator
user = User.find_by(username: submitted_username)
# step 2: compare tokens taking care to mitigate timing attacks and length leaks.
# (NB. favor *not* storing the token in plain text)
authenticated = ActiveSupport::SecurityUtils.secure_compare(
  # using digests mitigates length leaks
  ::Digest::SHA256.hexdigest(user.token),
  ::Digest::SHA256.hexdigest(submitted_token)
)
```


### Databases
- [ ] Beware any hand-written SQL snippets in the app and review for SQL injection vulnerabilities. Ensure SQL is appropriately sanitized using the ActiveRecord provided methods (e.g. see `sanitize_sql_array`).
- [ ] [Web application firewall](https://www.owasp.org/index.php/Web_Application_Firewall) that can detect, prevent, and alert on known SQL injection attempts.
- [ ] Keep Web application firewall rules up-to-date
- [ ] Minimize database privileges/access on user-serving database connections. Consider user accounts, database system OS user account, isolating data by views: https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#Additional_Defenses
- [ ] Minimize the data you store on users (especially PII) and regularly review if you can store less or delete older data. E.g. Does the app need to store a user's birthday in perpetuity (or at all) or only need it at registration to check they're old enough? Once data is no longer needed favor deleting it.
- [ ] Remove database links between user profiles and their data if possible: http://andre.arko.net/2014/09/20/how-to-safely-store-user-data/
- [ ] Favor storing data encrypted (https://github.com/rocketjob/symmetric-encryption)
- [ ] Do not store API keys, tokens, secret questions/answers and other secrets in plain text. Protect via hashing and/or encryption.
- [ ] Encrypted, frequent database backups that are regularly tested can be restored. Consider keeping offline backups.


### Redis
- [ ] Heroku Redis sounds like its insecure by default, secure it as described here using stunnel: https://devcenter.heroku.com/articles/securing-heroku-redis (*Does this affect most Redis setups? Are there any Redis providers who are more secure by default?*)
- *Seeking contributors to help with securing Redis, please open a PR and share your experience.*


### Gems
- [ ] Minimize production dependencies in Gemfile. Move all non-essential production gems into their own groups (usually test and development groups)
- [ ] Run Bundler Audit regularly (and/or Snyk/Gemnasium services)
- [ ] Update Bundler Audit vulnerability database regularly
- [ ] Review `bundle outdated` results regularly and act as needed


### Detecting Vulnerabilities
- [ ] Join, act on, and read code for alerts sent by [Rails Security mailing list](http://groups.google.com/group/rubyonrails-security)
- [ ] Brakeman (preferably Brakeman Pro) runs and results are reviewed regularly
- [ ] Update Brakeman regularly
- [ ] Security scanning service (e.g. Detectify)
- [ ] Provide ways for security researchers to work with you and report vulnerabilities responsibly


### Software Updates
- [ ] Update to always be on maintained versions of Rails. Many older Rails versions no longer receive security updates.
- [ ] Keep Ruby version up-to-date


### Test Coverage for Security Concerns
- [ ] Test coverage ("AbUser stories") for security-related code. Including but not limited to:
  - [ ] Account locking after X password attempt failures
  - [ ] Password change notifications sent
  - [ ] URL tampering (e.g. changing id values in the URL)
  - [ ] Attackers, including logged-in users, are blocked from priveleged actions and requests. For example, assume a logged-in user who is also an attacker does not need a "Delete" button to submit an HTTP request that would do the same. Attacker-crafted HTTP requests can be mimicked in request specs.


### Cross Site Scripting

- [ ] `html_safe`, `raw` などで `grep` してXSSが起きていないかレビューする


### Developer Hardware
- [ ] Prevent team members from storing production data and secrets on their machines
- [ ] Enable hard disk encryption on team members hardware


### Public, non-production Environments (Staging, Demo, etc.)
- [ ] Secure staging and test environments.
  - [ ] Should not leak data. Favor not using real data in these environments. Favor scrubbing data imported from production.
  - [ ] Avoid reusing secrets that are used in the production environment.
  - [ ] Favor limiting access to staging/test environments to certain IPs and/or other extra protections (e.g. HTTP basic credentials).
  - [ ] Prevent attackers making a genuine purchase on your staging site using well-known test payment methods (e.g. Stripe test credit card numbers)


### 正規表現

- [ ] `^` と `$` の代わりに、`\A` と `\z` を使うことを推奨します。 (http://guides.rubyonrails.org/security.html#regular-expressions)


### Handling Secrets
- [ ] Favor changing secrets when team members leave.
- [ ] Do not commit secrets to version control. Preventative measure: https://github.com/awslabs/git-secrets
- [ ] Purge version control history of any previously committed secrets.
- [ ] Consider changing any secrets that were previously committed to version control.


### Cookies
- [ ] Secure cookie flags
- [ ] Restrict cookie access as much as possible


### Headers
- [ ] Secure Headers (see [gem](https://github.com/twitter/secureheaders))
- [ ] Content Security Policy


### Assets
- [ ] Subresource Integrity for your assets and possibly 3rd party assets https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity


### TLS/SSL
- [ ] Force TLS/SSL on all URLs, including assets, images. No mixed protocols.
- [ ] Use SSL labs to check grade
- [ ] HSTS


### Traffic
- [ ] Rack Attack to limit requests and other security concerns
- [ ] Consider DDOS protections e.g. via CloudFlare


### Contacting Users
- [ ] Have rake task or similar ready to go for mass-password reset that will notify users of issue.
- [ ] Consider having multiple ways of contacting user (e.g. multiple emails) and sending important notifications through all of those channels.


### Regular Practices
- [ ] Add reminders in developer calendars to do the regular security tasks (e.g. those elsewhere in this checklist) and for checking if this checklist has changed recently.


### Further Reading
- [ ] Review and act on OWASPs literature on Ruby on Rails https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet
- [ ] More covered at http://guides.rubyonrails.org/security.html
- [ ] See http://cto-security-checklist.sqreen.io/
- [ ] _etc._


## Reminders

- Security concerns trump developer convenience. If having a secure-defaults `ApplicationController` feels like a pain in the neck when writing a public-facing controller that requires no authentication and no authorization checks, you're doing something right.
- Security is a moving target and is never done.
- The DRY principle is sometimes better ignored in security-related code when it prevents defence-in-depth, e.g. having authentication checks in `routes.rb` and controller callbacks is a form of duplication but provides better defence.

## Contributors

Contributions welcome!
