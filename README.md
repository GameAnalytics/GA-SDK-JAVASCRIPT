[![npm](https://img.shields.io/npm/v/gameanalytics.svg)](https://www.npmjs.com/package/gameanalytics)
[![npm](https://img.shields.io/npm/dt/gameanalytics.svg?label=npm%20downloads)](https://www.npmjs.com/package/gameanalytics)
[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)

GA-SDK-JAVASCRIPT
=================

Official repository for GameAnalytics JavaScript SDK. Written in Typescript.

Documentation can be found [here](https://gameanalytics.com/docs/javascript-sdk).

Changelog
---------
<!--(CHANGELOG_TOP)-->
**4.4.5**
* fixed enums in typescript decleration file

**4.4.4**
* changed event uuid field name

**4.4.3**
* added event uuid to events sent

**4.4.2**
* added error events to be sent for invalid custom event fields used
* added optional mergeFields argument to event methods to merge with global custom fields instead of overwrite them

**4.4.1**
* fixed missing custom event fields for when trying to fix missing session end events

**4.4.0**
* added global custom event fields function to allow to add custom fields to events sent automatically by the SDK

**4.3.1**
* added functionality to force a new user in a/b testing without having to uninstall app first, simply use custom user id function to set a new user id which hasn't been used yet

**4.3.0**
* added custom event fields feature

**4.2.3**
* added flutter to sdk version validator

**4.2.2**
* fixed addProgressionEvent score bug

**4.2.1**
* fixed ad event bug

**4.2.0**
* added before unload listener functions

**4.1.6**
* removed unused logs

**4.1.5**
* updated client ts validator

**4.1.4**
* corrected ad event annotation

**4.1.3**
* added godot to version validator

**4.1.2**
* small correction for support for KaiOS

**4.1.1**
* added support for KaiOS

**4.1.0**
* added ad event

**4.0.10**
* fixed bug to not send stored events from previous sessions (offline events or session end events not sent yet) by games on the same domain
* this bug fix can potentially affect metrics slightly so be aware of this as old stored events (offline events and session end events not sent yet) in games will not be sent with this new fix because internal keys for storing events in localstorage have changed now

**4.0.9**
* added better internal error reporting

**4.0.8**
* fixed cryptojs bug

**4.0.7**
* added session_num to init request

**4.0.6**
* removed gender, facebook and birthyear methods

**4.0.5**
* A/B testing fixes

**4.0.4**
* remote configs fixes

**4.0.3**
* small remote configs fix

**4.0.2**
* fixed events bug

**4.0.1**
* small bug fix for http requests

**4.0.0**
* Remote Config calls have been updated and the old calls have deprecated. Please see GA documentation for the new SDK calls and migration guide
* A/B testing support added

**3.1.2**
* declaration file fix

**3.1.1**
* typescript definition file fixed

**3.1.0**
* aded enable/disable event submission function

**3.0.3**
* fixed business event validation

**3.0.2**
* removed manual session handling check for startsession and endsession

**3.0.1**
* added missing function mappings

**3.0.0**
* added command center functionality

**2.1.5**
* fix to getbrowserversion for webviews on ios

**2.1.4**
* added custom dimensions to design and error events

**2.1.3**
* fixed not allowing to add events when session is not started
* fixed session length bug

**2.1.2**
* fixed browser version fetch to support facebook

**2.1.1**
* fixed null error on property 'running'

**2.1.0**
* fixed sending events request when no events to send
* added possiblity to change event process interval

**2.0.1**
* scoped javascript sdk namespace

**2.0.0**
* changed root namespace from 'ga' to 'gameanalytics'
* it is now possible to async load library on websites to avoid any delays when loading the website (just like it is possible with Google Analytics)

**1.1.11**
* added 'construct' to version validator

**1.0.10**
* bug fix for end session when using manual session handling

**1.0.9**
* bug fix for sending events straight after initializing sdk

**1.0.8**
* removed debug log messages for release distribution versions

**1.0.7**
* version validator updated with gamemaker

**1.0.6**
* small bug fix in validator

**1.0.5**
* added os version

**1.0.4**
* bug fix for GAEvents.fixMissingSessionEndEvents

**1.0.3**
* minor dependency fixes

**1.0.2**
* enabled to use sdk via npm

**1.0.1**
* fixed debug log messages to use console.log when console.debug is not available

**1.0.0**
* bumped to v1.0.0

**0.1.0**
* initial release
