# Cyclothone Android

The Android app uses system-browser OAuth, PKCE, and an exact `cyclothone://auth/callback` deep link. Google is never embedded in a WebView.

## Supabase setup required

Add this exact Redirect URL under Supabase Auth > URL Configuration:

`cyclothone://auth/callback`

The Google provider callback remains:

`https://whcomikcftbousoqzeal.supabase.co/auth/v1/callback`

No Google client secret is stored in the Android application.

## Flow

Android -> Supabase OAuth -> Google in system browser -> Supabase -> cyclothone:// callback -> PKCE code exchange -> authenticated Cyclothone WebView.