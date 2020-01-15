# Ievv auth
> Library for managing api keys and json web tokens

## INSTALL

```shell script
$ pip install ievv_auth
```

```python
INSTALLED_APPS = [
    ...
    'ievv_auth.ievv_api_key',
    'ievv_auth.ievv_jwt',
    ...
]
```

## Settings

See `ievv_auth.ievv_jwt.settings` for default settings

### Backend settings
How to override default settings:

```python
IEVV_JWT = {
    'default': {
        'ISSUER': 'ievv'
    }
}
```

Custom backends will use default settings, but you can also override settings for the particular backend:

```python
IEVV_JWT = {
    'backend-name': {
        'ISSUER': 'ievv'
    }
}
```

### global settings
How to override global settings:

```python
IEVV_JWT = {
    'global': {
        'AUTH_HEADER_TYPES': ('JWT',)
    }
}
```
