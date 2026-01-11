# CatGenie IoT API Endpoints

**Base URL:** `https://iot.petnovations.com`

**Total Endpoints:** 45

---

## Config API

### getBaseUrl
- **Method:** `GET`
- **Endpoint:** `config/v1/url`
- **Full URL:** `https://iot.petnovations.com/config/v1/url`
- **Auth Required:** No


## Device API

### getMyCats
- **Method:** `GET`
- **Endpoint:** `device/pet/user`
- **Full URL:** `https://iot.petnovations.com/device/pet/user`
- **Auth Required:** Yes ✅

### addCat
- **Method:** `POST`
- **Endpoint:** `device/pet`
- **Full URL:** `https://iot.petnovations.com/device/pet`
- **Auth Required:** Yes ✅

### deleteCat
- **Method:** `DELETE`
- **Endpoint:** `device/pet`
- **Full URL:** `https://iot.petnovations.com/device/pet`
- **Auth Required:** Yes ✅

### updateCat
- **Method:** `PUT`
- **Endpoint:** `device/pet`
- **Full URL:** `https://iot.petnovations.com/device/pet`
- **Auth Required:** Yes ✅

### getThing
- **Method:** `GET`
- **Endpoint:** `device/v1/thing`
- **Full URL:** `https://iot.petnovations.com/device/v1/thing`
- **Auth Required:** Yes ✅

### userDeviceAssociation
- **Method:** `POST`
- **Endpoint:** `device/device/association`
- **Full URL:** `https://iot.petnovations.com/device/device/association`
- **Auth Required:** Yes ✅

### deAssociateDevice
- **Method:** `DELETE`
- **Endpoint:** `device/device/association`
- **Full URL:** `https://iot.petnovations.com/device/device/association`
- **Auth Required:** Yes ✅

### getMyDevices
- **Method:** `GET`
- **Endpoint:** `device/device/v2`
- **Full URL:** `https://iot.petnovations.com/device/device/v2`
- **Auth Required:** Yes ✅

### approveFirmwareUpdate
- **Method:** `PUT`
- **Endpoint:** `device/update`
- **Full URL:** `https://iot.petnovations.com/device/update`
- **Auth Required:** Yes ✅

### getVersionComments
- **Method:** `GET`
- **Endpoint:** `device/update/versions/comments`
- **Full URL:** `https://iot.petnovations.com/device/update/versions/comments`
- **Auth Required:** Yes ✅

### updateLanguage
- **Method:** `PATCH`
- **Endpoint:** `device/update/languages/selectLanguage/device`
- **Full URL:** `https://iot.petnovations.com/device/update/languages/selectLanguage/device`
- **Auth Required:** Yes ✅

### updateGenieName
- **Method:** `PUT`
- **Endpoint:** `device/management/gateway`
- **Full URL:** `https://iot.petnovations.com/device/management/gateway`
- **Auth Required:** Yes ✅

### getPetStatistics
- **Method:** `GET`
- **Endpoint:** `device/history/account/pet/statistics`
- **Full URL:** `https://iot.petnovations.com/device/history/account/pet/statistics`
- **Auth Required:** Yes ✅

### deviceOperation
- **Method:** `POST`
- **Endpoint:** `device/management`
- **Full URL:** `https://iot.petnovations.com/device/management`
- **Auth Required:** Yes ✅

### deviceConfig
- **Method:** `PUT`
- **Endpoint:** `device/management`
- **Full URL:** `https://iot.petnovations.com/device/management`
- **Auth Required:** Yes ✅

### preAssociate
- **Method:** `POST`
- **Endpoint:** `device/device/association`
- **Full URL:** `https://iot.petnovations.com/device/device/association`
- **Auth Required:** Yes ✅

### getCertificateUrl
- **Method:** `POST`
- **Endpoint:** `device/mainBoard`
- **Full URL:** `https://iot.petnovations.com/device/mainBoard`
- **Auth Required:** Yes ✅

### activateCertificate
- **Method:** `PUT`
- **Endpoint:** `device/mainBoard`
- **Full URL:** `https://iot.petnovations.com/device/mainBoard`
- **Auth Required:** Yes ✅

### getCatGenieByMacAddress
- **Method:** `GET`
- **Endpoint:** `device/mainBoard`
- **Full URL:** `https://iot.petnovations.com/device/mainBoard`
- **Auth Required:** Yes ✅

### sendActicationCode
- **Method:** `PUT`
- **Endpoint:** `device/activation/use`
- **Full URL:** `https://iot.petnovations.com/device/activation/use`
- **Auth Required:** Yes ✅


## Facade API

### sendFeedback
- **Method:** `POST`
- **Endpoint:** `facade/v1/mobile-user/feedback`
- **Full URL:** `https://iot.petnovations.com/facade/v1/mobile-user/feedback`
- **Auth Required:** Yes ✅


## Gateway API

### acceptInvitation
- **Method:** `POST`
- **Endpoint:** `gateway/acceptShareAccountInvitation`
- **Full URL:** `https://iot.petnovations.com/gateway/acceptShareAccountInvitation`
- **Auth Required:** Yes ✅

### deleteUserAccount
- **Method:** `DELETE`
- **Endpoint:** `gateway/deleteUserInfo`
- **Full URL:** `https://iot.petnovations.com/gateway/deleteUserInfo`
- **Auth Required:** Yes ✅


## Notification API

### attachMobile
- **Method:** `POST`
- **Endpoint:** `notification/v1/mobile/attach`
- **Full URL:** `https://iot.petnovations.com/notification/v1/mobile/attach`
- **Auth Required:** Yes ✅

### updateMobile
- **Method:** `PUT`
- **Endpoint:** `notification/v1/mobile/updateMobile`
- **Full URL:** `https://iot.petnovations.com/notification/v1/mobile/updateMobile`
- **Auth Required:** Yes ✅

### getNotifications
- **Method:** `GET`
- **Endpoint:** `notification/v1/push/user`
- **Full URL:** `https://iot.petnovations.com/notification/v1/push/user`
- **Auth Required:** Yes ✅

### deleteNotification
- **Method:** `DELETE`
- **Endpoint:** `notification/v1/push`
- **Full URL:** `https://iot.petnovations.com/notification/v1/push`
- **Auth Required:** Yes ✅

### deleteNotificationsByTypes
- **Method:** `DELETE`
- **Endpoint:** `notification/v1/push/forUserByType`
- **Full URL:** `https://iot.petnovations.com/notification/v1/push/forUserByType`
- **Auth Required:** Yes ✅

### updateNotificationsConfig
- **Method:** `PUT`
- **Endpoint:** `notification/v1/push/settings`
- **Full URL:** `https://iot.petnovations.com/notification/v1/push/settings`
- **Auth Required:** Yes ✅

### getNotificationsConfig
- **Method:** `GET`
- **Endpoint:** `notification/v1/push/settings`
- **Full URL:** `https://iot.petnovations.com/notification/v1/push/settings`
- **Auth Required:** Yes ✅


## Ums API

### LOGIN_BY_PHONE_NUMBER
- **Method:** `POST`
- **Endpoint:** `ums/v1/users/loginByPhoneNumber/v2`
- **Full URL:** `https://iot.petnovations.com/ums/v1/users/loginByPhoneNumber/v2`
- **Auth Required:** No

### GENERATE_LOGIN_CODE
- **Method:** `POST`
- **Endpoint:** `ums/v1/users/generateLoginCode/v2`
- **Full URL:** `https://iot.petnovations.com/ums/v1/users/generateLoginCode/v2`
- **Auth Required:** No

### updateClientDetails
- **Method:** `PUT`
- **Endpoint:** `ums/v1/users`
- **Full URL:** `https://iot.petnovations.com/ums/v1/users`
- **Auth Required:** Yes ✅

### getAccountUsers
- **Method:** `GET`
- **Endpoint:** `ums/v1/account/`
- **Full URL:** `https://iot.petnovations.com/ums/v1/account/`
- **Auth Required:** Yes ✅

### leaveAccount
- **Method:** `DELETE`
- **Endpoint:** `ums/v1/account/`
- **Full URL:** `https://iot.petnovations.com/ums/v1/account/`
- **Auth Required:** Yes ✅

### removeUserFromAccount
- **Method:** `DELETE`
- **Endpoint:** `ums/v1/account/member`
- **Full URL:** `https://iot.petnovations.com/ums/v1/account/member`
- **Auth Required:** Yes ✅

### changeAdmin
- **Method:** `POST`
- **Endpoint:** `ums/v1/account/ownership/member`
- **Full URL:** `https://iot.petnovations.com/ums/v1/account/ownership/member`
- **Auth Required:** Yes ✅

### getInvitaions
- **Method:** `GET`
- **Endpoint:** `ums/v1/account/invitations/share`
- **Full URL:** `https://iot.petnovations.com/ums/v1/account/invitations/share`
- **Auth Required:** Yes ✅

### inviteAccount
- **Method:** `PUT`
- **Endpoint:** `ums/v1/account/invitations/share`
- **Full URL:** `https://iot.petnovations.com/ums/v1/account/invitations/share`
- **Auth Required:** Yes ✅

### rejectInvitation
- **Method:** `POST`
- **Endpoint:** `ums/v1/account/invitations/share`
- **Full URL:** `https://iot.petnovations.com/ums/v1/account/invitations/share`
- **Auth Required:** Yes ✅

### deleteShareAccountInvitation
- **Method:** `DELETE`
- **Endpoint:** `ums/v1/account/invitations/share`
- **Full URL:** `https://iot.petnovations.com/ums/v1/account/invitations/share`
- **Auth Required:** Yes ✅

### updateReviewStatus
- **Method:** `PATCH`
- **Endpoint:** `ums/v1/feedback/reviewStatus`
- **Full URL:** `https://iot.petnovations.com/ums/v1/feedback/reviewStatus`
- **Auth Required:** Yes ✅

### generateLoginCode
- **Method:** `POST`
- **Endpoint:** `ums/v1/users/generateLoginCode/v2`
- **Full URL:** `https://iot.petnovations.com/ums/v1/users/generateLoginCode/v2`
- **Auth Required:** No

### loginByPhoneNumber
- **Method:** `POST`
- **Endpoint:** `ums/v1/users/loginByPhoneNumber/v2`
- **Full URL:** `https://iot.petnovations.com/ums/v1/users/loginByPhoneNumber/v2`
- **Auth Required:** No


## Firmware Update Flow

### Step 1: Get Device Data
```
GET https://iot.petnovations.com/device/device/v2
```
Returns device list with firmware info including:
- Current firmware version
- Available firmware update (if any)

### Step 2: Get Firmware Comments/Notes
```
GET https://iot.petnovations.com/device/update/versions/comments?version=X.X.X
```
Returns release notes for the firmware version

### Step 3: Approve Firmware Update
```
PUT https://iot.petnovations.com/device/update/{deviceId}/approve
```
Body:
```json
{
  "version": "X.X.X",
  "configurationId": "config-id"
}
```

### Step 4: Firmware Download
**Note:** The actual firmware binary download mechanism is likely:
1. Device receives notification via MQTT/WebSocket that update is approved
2. Device downloads firmware from AWS S3 or similar cloud storage
3. Firmware is transferred to CatGenie device via Bluetooth

## Testing Commands

### Get Devices (requires auth token)
```bash
# You need an authentication token from the app
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  https://iot.petnovations.com/device/device/v2
```

### Get Firmware Comments (requires auth)
```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  "https://iot.petnovations.com/device/update/versions/comments?version=1.0.0"
```

