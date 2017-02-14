// Copyright 2010 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// This code was generated by google-apis-code-generator 1.5.1
//   Build date: 2016-07-08 17:28:43 UTC
//   on: 2016-08-08, 17:19:17 UTC
//   C++ generator version: 0.1.4

// ----------------------------------------------------------------------------
// NOTE: This file is generated from Google APIs Discovery Service.
// Service:
//   Gmail API (gmail/v1)
// Description:
//   Access Gmail mailboxes including sending user email.
// Classes:
//   Profile
// Documentation:
//   https://developers.google.com/gmail/api/

#include "google/gmail_api/profile.h"
#include <string>
#include "googleapis/base/integral_types.h"
#include "googleapis/client/data/jsoncpp_data.h"
#include "googleapis/strings/stringpiece.h"


#include <string>
#include "googleapis/strings/strcat.h"

namespace google_gmail_api {
using namespace googleapis;


// Object factory method (static).
Profile* Profile::New() {
  return new client::JsonCppCapsule<Profile>;
}

// Standard immutable constructor.
Profile::Profile(const Json::Value& storage)
  : client::JsonCppData(storage) {
}

// Standard mutable constructor.
Profile::Profile(Json::Value* storage)
  : client::JsonCppData(storage) {
}

// Standard destructor.
Profile::~Profile() {
}
}  // namespace google_gmail_api
