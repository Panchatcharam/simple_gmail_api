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
#ifndef  GOOGLE_GMAIL_API_VACATION_SETTINGS_H_
#define  GOOGLE_GMAIL_API_VACATION_SETTINGS_H_

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
 * Vacation auto-reply settings for an account. These settings correspond to the
 * "Vacation responder" feature in the web interface. See  for more details.
 *
 * @ingroup DataObject
 */
class VacationSettings : public client::JsonCppData {
 public:
  /**
   * Creates a new default instance.
   *
   * @return Ownership is passed back to the caller.
   */
  static VacationSettings* New();

  /**
   * Standard constructor for an immutable data object instance.
   *
   * @param[in] storage  The underlying data storage for this instance.
   */
  explicit VacationSettings(const Json::Value& storage);

  /**
   * Standard constructor for a mutable data object instance.
   *
   * @param[in] storage  The underlying data storage for this instance.
   */
  explicit VacationSettings(Json::Value* storage);

  /**
   * Standard destructor.
   */
  virtual ~VacationSettings();

  /**
   * Returns a string denoting the type of this data object.
   *
   * @return <code>google_gmail_api::VacationSettings</code>
   */
  const StringPiece GetTypeName() const {
    return StringPiece("google_gmail_api::VacationSettings");
  }

  /**
   * Determine if the '<code>enableAutoReply</code>' attribute was set.
   *
   * @return true if the '<code>enableAutoReply</code>' attribute was set.
   */
  bool has_enable_auto_reply() const {
    return Storage().isMember("enableAutoReply");
  }

  /**
   * Clears the '<code>enableAutoReply</code>' attribute.
   */
  void clear_enable_auto_reply() {
    MutableStorage()->removeMember("enableAutoReply");
  }


  /**
   * Get the value of the '<code>enableAutoReply</code>' attribute.
   */
  bool get_enable_auto_reply() const {
    const Json::Value& storage = Storage("enableAutoReply");
    return client::JsonValueToCppValueHelper<bool >(storage);
  }

  /**
   * Change the '<code>enableAutoReply</code>' attribute.
   *
   * Flag that controls whether Gmail automatically replies to messages.
   *
   * @param[in] value The new value.
   */
  void set_enable_auto_reply(bool value) {
    client::SetJsonValueFromCppValueHelper<bool >(
      value, MutableStorage("enableAutoReply"));
  }

  /**
   * Determine if the '<code>endTime</code>' attribute was set.
   *
   * @return true if the '<code>endTime</code>' attribute was set.
   */
  bool has_end_time() const {
    return Storage().isMember("endTime");
  }

  /**
   * Clears the '<code>endTime</code>' attribute.
   */
  void clear_end_time() {
    MutableStorage()->removeMember("endTime");
  }


  /**
   * Get the value of the '<code>endTime</code>' attribute.
   */
  int64 get_end_time() const {
    const Json::Value& storage = Storage("endTime");
    return client::JsonValueToCppValueHelper<int64 >(storage);
  }

  /**
   * Change the '<code>endTime</code>' attribute.
   *
   * An optional end time for sending auto-replies (epoch ms). When this is
   * specified, Gmail will automatically reply only to messages that it receives
   * before the end time. If both startTime and endTime are specified, startTime
   * must precede endTime.
   *
   * @param[in] value The new value.
   */
  void set_end_time(int64 value) {
    client::SetJsonValueFromCppValueHelper<int64 >(
      value, MutableStorage("endTime"));
  }

  /**
   * Determine if the '<code>responseBodyHtml</code>' attribute was set.
   *
   * @return true if the '<code>responseBodyHtml</code>' attribute was set.
   */
  bool has_response_body_html() const {
    return Storage().isMember("responseBodyHtml");
  }

  /**
   * Clears the '<code>responseBodyHtml</code>' attribute.
   */
  void clear_response_body_html() {
    MutableStorage()->removeMember("responseBodyHtml");
  }


  /**
   * Get the value of the '<code>responseBodyHtml</code>' attribute.
   */
  const StringPiece get_response_body_html() const {
    const Json::Value& v = Storage("responseBodyHtml");
    if (v == Json::Value::null) return StringPiece("");
    return StringPiece(v.asCString());
  }

  /**
   * Change the '<code>responseBodyHtml</code>' attribute.
   *
   * Response body in HTML format. Gmail will sanitize the HTML before storing
   * it.
   *
   * @param[in] value The new value.
   */
  void set_response_body_html(const StringPiece& value) {
    *MutableStorage("responseBodyHtml") = value.data();
  }

  /**
   * Determine if the '<code>responseBodyPlainText</code>' attribute was set.
   *
   * @return true if the '<code>responseBodyPlainText</code>' attribute was set.
   */
  bool has_response_body_plain_text() const {
    return Storage().isMember("responseBodyPlainText");
  }

  /**
   * Clears the '<code>responseBodyPlainText</code>' attribute.
   */
  void clear_response_body_plain_text() {
    MutableStorage()->removeMember("responseBodyPlainText");
  }


  /**
   * Get the value of the '<code>responseBodyPlainText</code>' attribute.
   */
  const StringPiece get_response_body_plain_text() const {
    const Json::Value& v = Storage("responseBodyPlainText");
    if (v == Json::Value::null) return StringPiece("");
    return StringPiece(v.asCString());
  }

  /**
   * Change the '<code>responseBodyPlainText</code>' attribute.
   *
   * Response body in plain text format.
   *
   * @param[in] value The new value.
   */
  void set_response_body_plain_text(const StringPiece& value) {
    *MutableStorage("responseBodyPlainText") = value.data();
  }

  /**
   * Determine if the '<code>responseSubject</code>' attribute was set.
   *
   * @return true if the '<code>responseSubject</code>' attribute was set.
   */
  bool has_response_subject() const {
    return Storage().isMember("responseSubject");
  }

  /**
   * Clears the '<code>responseSubject</code>' attribute.
   */
  void clear_response_subject() {
    MutableStorage()->removeMember("responseSubject");
  }


  /**
   * Get the value of the '<code>responseSubject</code>' attribute.
   */
  const StringPiece get_response_subject() const {
    const Json::Value& v = Storage("responseSubject");
    if (v == Json::Value::null) return StringPiece("");
    return StringPiece(v.asCString());
  }

  /**
   * Change the '<code>responseSubject</code>' attribute.
   *
   * Optional text to prepend to the subject line in vacation responses. In
   * order to enable auto-replies, either the response subject or the response
   * body must be nonempty.
   *
   * @param[in] value The new value.
   */
  void set_response_subject(const StringPiece& value) {
    *MutableStorage("responseSubject") = value.data();
  }

  /**
   * Determine if the '<code>restrictToContacts</code>' attribute was set.
   *
   * @return true if the '<code>restrictToContacts</code>' attribute was set.
   */
  bool has_restrict_to_contacts() const {
    return Storage().isMember("restrictToContacts");
  }

  /**
   * Clears the '<code>restrictToContacts</code>' attribute.
   */
  void clear_restrict_to_contacts() {
    MutableStorage()->removeMember("restrictToContacts");
  }


  /**
   * Get the value of the '<code>restrictToContacts</code>' attribute.
   */
  bool get_restrict_to_contacts() const {
    const Json::Value& storage = Storage("restrictToContacts");
    return client::JsonValueToCppValueHelper<bool >(storage);
  }

  /**
   * Change the '<code>restrictToContacts</code>' attribute.
   *
   * Flag that determines whether responses are sent to recipients who are not
   * in the user's list of contacts.
   *
   * @param[in] value The new value.
   */
  void set_restrict_to_contacts(bool value) {
    client::SetJsonValueFromCppValueHelper<bool >(
      value, MutableStorage("restrictToContacts"));
  }

  /**
   * Determine if the '<code>restrictToDomain</code>' attribute was set.
   *
   * @return true if the '<code>restrictToDomain</code>' attribute was set.
   */
  bool has_restrict_to_domain() const {
    return Storage().isMember("restrictToDomain");
  }

  /**
   * Clears the '<code>restrictToDomain</code>' attribute.
   */
  void clear_restrict_to_domain() {
    MutableStorage()->removeMember("restrictToDomain");
  }


  /**
   * Get the value of the '<code>restrictToDomain</code>' attribute.
   */
  bool get_restrict_to_domain() const {
    const Json::Value& storage = Storage("restrictToDomain");
    return client::JsonValueToCppValueHelper<bool >(storage);
  }

  /**
   * Change the '<code>restrictToDomain</code>' attribute.
   *
   * Flag that determines whether responses are sent to recipients who are
   * outside of the user's domain. This feature is only available for Google
   * Apps users.
   *
   * @param[in] value The new value.
   */
  void set_restrict_to_domain(bool value) {
    client::SetJsonValueFromCppValueHelper<bool >(
      value, MutableStorage("restrictToDomain"));
  }

  /**
   * Determine if the '<code>startTime</code>' attribute was set.
   *
   * @return true if the '<code>startTime</code>' attribute was set.
   */
  bool has_start_time() const {
    return Storage().isMember("startTime");
  }

  /**
   * Clears the '<code>startTime</code>' attribute.
   */
  void clear_start_time() {
    MutableStorage()->removeMember("startTime");
  }


  /**
   * Get the value of the '<code>startTime</code>' attribute.
   */
  int64 get_start_time() const {
    const Json::Value& storage = Storage("startTime");
    return client::JsonValueToCppValueHelper<int64 >(storage);
  }

  /**
   * Change the '<code>startTime</code>' attribute.
   *
   * An optional start time for sending auto-replies (epoch ms). When this is
   * specified, Gmail will automatically reply only to messages that it receives
   * after the start time. If both startTime and endTime are specified,
   * startTime must precede endTime.
   *
   * @param[in] value The new value.
   */
  void set_start_time(int64 value) {
    client::SetJsonValueFromCppValueHelper<int64 >(
      value, MutableStorage("startTime"));
  }

 private:
  void operator=(const VacationSettings&);
};  // VacationSettings
}  // namespace google_gmail_api
#endif  // GOOGLE_GMAIL_API_VACATION_SETTINGS_H_
