def custom_userinfo_claims(claims, user):
    claims['sub'] = user.username
    claims['did'] = user.username
    claims['preferred_username'] = user.username
    claims['did_method'] = user.username.split(':')[1] if user.username.count(':') >= 2 else 'key'
    return claims


def custom_idtoken_processing_hook(id_token, user, token, request):
    id_token['did'] = user.username
    id_token['did_method'] = user.username.split(':')[1] if user.username.count(':') >= 2 else 'key'
    return id_token


def custom_sub_generator(user):
    return user.username
