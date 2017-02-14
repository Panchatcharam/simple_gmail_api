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
// Generated from:
//   Version: v1
//   Revision: 48
// Generated by:
//    Tool: google-apis-code-generator 1.5.1
//     C++: 0.1.4
#ifndef  GOOGLE_GMAIL_API_HISTORY_LABEL_REMOVED_H_
#define  GOOGLE_GMAIL_API_HISTORY_LABEL_REMOVED_H_

#include <string>
#include "googleapis/base/macros.h"
#include "googleapis/client/data/jsoncpp_data.h"
#include "googleapis/strings/stringpiece.h"

#include "google/gmail_api/message.h"

namespace Json {
class Value;
}  // namespace Json

namespace google_gmail_api {
using namespace googleapis;

/**
 * No description provided.
 *
 * @ingroup DataObject
 */
class HistoryLabelRemoved : public client::JsonCppData {
 public:
  /**
   * Creates a new default instance.
   *
   * @return Ownership is passed back to the caller.
   */
  static HistoryLabelRemoved* New();

  /**
   * Standard constructor for an immutable data object instance.
   *
   * @param[in] storage  The underlying data storage for this instance.
   */
  explicit HistoryLabelRemoved(const Json::Value& storage);

  /**
   * Standard constructor for a mutable data object instance.
   *
   * @param[in] storage  The underlying data storage for this instance.
   */
  explicit HistoryLabelRemoved(Json::Value* storage);

  /**
   * Standard destructor.
   */
  virtual ~HistoryLabelRemoved();

  /**
   * Returns a string denoting the type of this data object.
   *
   * @return <code>google_gmail_api::HistoryLabelRemoved</code>
   */
  const StringPiece GetTypeName() const {
    return StringPiece("google_gmail_api::HistoryLabelRemoved");
  }

  /**
   * Determine if the '<code>labelIds</code>' attribute was set.
   *
   * @return true if the '<code>labelIds</code>' attribute was set.
   */
  bool has_label_ids() const {
    return Storage().isMember("labelIds");
  }

  /**
   * Clears the '<code>labelIds</code>' attribute.
   */
  void clear_label_ids() {
    MutableStorage()->removeMember("labelIds");
  }


  /**
   * Get a reference to the value of the '<code>labelIds</code>' attribute.
   */
  const client::JsonCppArray<string > get_label_ids() const {
     const Json::Value& storage = Storage("labelIds");
    return client::JsonValueToCppValueHelper<client::JsonCppArray<string > >(storage);
  }

  /**
   * Gets a reference to a mutable value of the '<code>labelIds</code>'
   * property.
   *
   * Label IDs removed from the message.
   *
   * @return The result can be modified to change the attribute value.
   */
  client::JsonCppArray<string > mutable_labelIds() {
    Json::Value* storage = MutableStorage("labelIds");
    return client::JsonValueToMutableCppValueHelper<client::JsonCppArray<string > >(storage);
  }

  /**
   * Determine if the '<code>message</code>' attribute was set.
   *
   * @return true if the '<code>message</code>' attribute was set.
   */
  bool has_message() const {
    return Storage().isMember("message");
  }

  /**
   * Clears the '<code>message</code>' attribute.
   */
  void clear_message() {
    MutableStorage()->removeMember("message");
  }


  /**
   * Get a reference to the value of the '<code>message</code>' attribute.
   */
  const Message get_message() const;

  /**
   * Gets a reference to a mutable value of the '<code>message</code>' property.
   * @return The result can be modified to change the attribute value.
   */
  Message mutable_message();

 private:
  void operator=(const HistoryLabelRemoved&);
};  // HistoryLabelRemoved
}  // namespace google_gmail_api
#endif  // GOOGLE_GMAIL_API_HISTORY_LABEL_REMOVED_H_
