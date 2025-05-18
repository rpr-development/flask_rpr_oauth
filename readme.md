```markdown
# rpr_oauth

`rpr_oauth` is een Python-package dat OAuth-functionaliteit biedt voor Flask-applicaties. Het bevat hulpmiddelen voor authenticatie, tokenbeheer, en sessiebeheer. Deze package is ontworpen om eenvoudig te integreren in een bestaande Flask-applicatie.

## Installatie

1. Clone de repository naar je lokale machine.
2. Installeer de vereisten met pip:
   ```bash
   pip install -r requirements.txt
   ```
3. Voeg de package toe aan je Flask-applicatie.

## Functionaliteiten

### Decorators

De package bevat twee decorators om routes te beveiligen:

1. **`@oauth_required`**  
   Controleert of de gebruiker is geauthenticeerd en of de OAuth-token geldig is. Als de token is verlopen, wordt geprobeerd deze te vernieuwen. Als dat niet lukt, wordt de gebruiker doorgestuurd naar de loginpagina.

2. **`@oauth_2fa_required`**  
   Controleert naast de standaard OAuth-authenticatie ook of de gebruiker 2FA (twee-factor-authenticatie) heeft voltooid. Als 2FA vereist is en niet is voltooid, wordt de gebruiker doorgestuurd naar de loginpagina.

### Getters

De package biedt verschillende functies om gegevens uit de sessie op te halen, zoals:
- `get_user_id()`: Haalt de gebruikers-ID op.
- `get_token()`: Haalt de OAuth-token op.
- `get_refresh_token()`: Haalt de refresh-token op.
- `get_expires_at()`: Haalt de vervaltijd van de token op.
- `get_is_2fa()`: Controleert of 2FA is gevalideerd.
- `is_authenticated()`: Controleert of de gebruiker is geauthenticeerd.

### Hulpfuncties

- **`redirect_to_login(needing_2fa=False)`**  
  Stuurt de gebruiker door naar de loginpagina. Als 2FA vereist is, wordt dit aangegeven in de queryparameters.

- **`is_token_expired()`**  
  Controleert of de huidige OAuth-token is verlopen.

- **`refresh_token(needing_2fa=False)`**  
  Vernieuwt de OAuth-token met behulp van de refresh-token. Als dit niet lukt, wordt de gebruiker uitgelogd en doorgestuurd naar de loginpagina.

- **`set_oauth(user_id, access_token, refresh_token, expires_at, twofa_validated=False)`**  
  Logt de gebruiker in door de sessie te vullen met de verstrekte gegevens.

- **`unset_oauth()`**  
  Logt de gebruiker uit door de sessie te wissen.

## Flask Routes

De package bevat een route voor het verwerken van de OAuth-callback:

### `/oauth/callback`

- **Methode**: `GET`, `POST`
- **Beschrijving**: Verwerkt de callback van de OAuth-provider. Het haalt de tokens en gebruikersinformatie op uit de queryparameters en logt de gebruiker in.
- **Codevoorbeeld**:
  ```python
  @oauth.route('/callback', methods=['GET', 'POST'])
  def callback():
      token = request.args.get("access_token")
      refresh_token = request.args.get("refresh_token")
      expires_at = request.args.get("expires_at")
      user_id = request.args.get("user_id")

      if not token or not refresh_token or not expires_at or not user_id:
          raise Exception("Missing token information")

      set_oauth(
          user_id,
          token,
          refresh_token,
          expires_at,
          request.args.get("2fa_needed", False)
      )

      return redirect(session.pop("next_page", url_for("main.index")))
  ```

## Configuratie

De package gebruikt de omgevingsvariabele `RPR_OAUTH_BASE_URL` om de basis-URL van de OAuth-server te bepalen. Als deze niet is ingesteld, wordt standaard `https://auth.roleplayreality.nl` gebruikt.

## Gebruik

1. Voeg de `rpr_oauth`-package toe aan je Flask-applicatie:
   ```python
   from rpr_oauth import oauth_required, oauth_2fa_required
   from rpr_oauth.routes import oauth

   app.register_blueprint(oauth)
   ```

2. Beveilig routes met de decorators:
   ```python
   @app.route('/protected')
   @oauth_required
   def protected_route():
       return "Je bent geauthenticeerd!"

   @app.route('/protected-2fa')
   @oauth_2fa_required
   def protected_2fa_route():
       return "Je bent geauthenticeerd met 2FA!"
   ```

3. Zorg ervoor dat de OAuth-server correct is geconfigureerd om de callback-URL (`/oauth/callback`) te ondersteunen.

## Bijdragen

Voel je vrij om bij te dragen aan dit project door pull requests in te dienen of issues te melden.

## Licentie

Dit project is gelicenseerd onder de MIT-licentie.
```

Laat me weten of je nog aanpassingen of uitbreidingen wilt!
