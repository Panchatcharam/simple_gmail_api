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
#ifndef  GOOGLE_GMAIL_API_MESSAGE_PART_BODY_H_
#define  GOOGLE_GMAIL_API_MESSAGE_PART_BODY_H_

#include <string>
#include "googleapis/base/integral_types.h"
#include "googleapis/base/macros.h"
#include "googleapis/client/data/jsoncpp_data.h"
#include "googleapis/strings/stringpiece.h"

namespace Json {
class Value;
}  // namespace Json

namespace google_gmail_api {
using namespace googleapis;

/**
 * The body of a single MIME message part.
 *
 * @ingroup DataObject
 */
class MessagePartBody : public client::JsonCppData {
 public:
  /**
   * Creates a new default instance.
   *
   * @return Ownership is passed back to the caller.
   */
  static MessagePartBody* New();

  /**
   * Standard constructor for an immutable data object instance.
   *
   * @param[in] storage  The underlying data storage for this instance.
   */
  explicit MessagePartBody(const Json::Value& storage);

  /**
   * Standard constructor for a mutable data object instance.
   *
   * @param[in] storage  The underlying data storage for this instance.
   */
  explicit MessagePartBody(Json::Value* storage);

  /**
   * Standard destructor.
   */
  virtual ~MessagePartBody();

  /**
   * Returns a string denoting the type of this data object.
   *
   * @return <code>google_gmail_api::MessagePartBody</code>
   */
  const StringPiece GetTypeName() const {
    return StringPiece("google_gmail_api::MessagePartBody");
  }

  /**
   * Determine if the '<code>attachmentId</code>' attribute was set.
   *
   * @return true if the '<code>attachmentId</code>' attribute was set.
   */
  bool has_attachment_id() const {
    return Storage().isMember("attachmentId");
  }

  /**
   * Clears the '<code>attachmentId</code>' attribute.
   */
  void clear_attachment_id() {
    MutableStorage()->removeMember("attachmentId");
  }


  /**
   * Get the value of the '<code>attachmentId</code>' attribute.
   */
  const StringPiece get_attachment_id() const {
    const Json::Value& v = Storage("attachmentId");
    if (v == Json::Value::null) return StringPiece("");
    return StringPiece(v.asCString());
  }

  /**
   * Change the '<code>attachmentId</code>' attribute.
   *
   * When present, contains the ID of an external attachment that can be
   * retrieved in a separate messages.attachments.get request. When not present,
   * the entire content of the message part body is contained in the data field.
   *
   * @param[in] value The new value.
   */
  void set_attachment_id(const StringPiece& value) {
    *MutableStorage("attachmentId") = value.data();
  }

  /**
   * Determine if the '<code>data</code>' attribute was set.
   *
   * @return true if the '<code>data</code>' attribute was set.
   */
  bool has_data() const {
    return Storage().isMember("data");
  }

  /**
   * Clears the '<code>data</code>' attribute.
   */
  void clear_data() {
    MutableStorage()->removeMember("data");
  }


  /**
   * Get the value of the '<code>data</code>' attribute.
   */
  const StringPiece get_data() const {
    const Json::Value& v = Storage("data");
    if (v == Json::Value::null) return StringPiece("");
    return StringPiece(v.asCString());
  }

  /**
   * Change the '<code>data</code>' attribute.
   *
   * The body data of a MIME message part. May be empty for MIME container types
   * that have no message body or when the body data is sent as a separate
   * attachment. An attachment ID is present if the body data is contained in a
   * separate attachment.
   *
   * @param[in] value The new value.
   */
  void set_data(const StringPiece& value) {
    *MutableStorage("data") = value.data();
  }

  /**
   * Determine if the '<code>size</code>' attribute was set.
   *
   * @return true if the '<code>size</code>' attribute was set.
   */
  bool has_size() const {
    return Storage().isMember("size");
  }

  /**
   * Clears the '<code>size</code>' attribute.
   */
  void clear_size() {
    MutableStorage()->removeMember("size");
  }


  /**
   * Get the value of the '<code>size</code>' attribute.
   */
  int32 get_size() const {
    const Json::Value& storage = Storage("size");
    return client::JsonValueToCppValueHelper<int32 >(storage);
  }

  /**
   * Change the '<code>size</code>' attribute.
   *
   * Total number of bytes in the body of the message part.
   *
   * @param[in] value The new value.
   */
  void set_size(int32 value) {
    client::SetJsonValueFromCppValueHelper<int32 >(
      value, MutableStorage("size"));
  }

 private:
  void operator=(const MessagePartBody&);
};  // MessagePartBody
}  // namespace google_gmail_api
#endif  // GOOGLE_GMAIL_API_MESSAGE_PART_BODY_H_