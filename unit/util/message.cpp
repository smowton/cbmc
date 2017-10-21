/*******************************************************************\

 Module: Messaget tests

 Author: Diffblue Limited. All rights reserved.

\*******************************************************************/

#include <catch.hpp>
#include <util/message.h>
#include <sstream>
#include <string.h>

TEST_CASE("Copy a messaget")
{
  std::ostringstream sstream1, sstream2;
  stream_message_handlert handler1(sstream1), handler2(sstream2);

  messaget msg1(handler1);

  // Copy messaget:
  messaget msg2(msg1);

  // Change its handler:
  msg2.set_message_handler(handler2);

  msg2.status() << "Test" << messaget::eom;

  CHECK(sstream1.str()=="");
  CHECK(sstream2.str()=="Test\n");
}

TEST_CASE("Copy a messaget, with deletion of the old messaget")
{
  std::ostringstream sstream1, sstream2;
  stream_message_handlert handler1(sstream1), handler2(sstream2);

  char msg1_storage[sizeof(messaget)];
  // Placement-new msg1, storing it in msg1_storage.
  messaget &msg1=*new(msg1_storage) messaget(handler1);

  // Copy messaget:
  messaget msg2(msg1);

  // Change its handler:
  msg2.set_message_handler(handler2);

  // Delete the old handler and trash its storage, to check that it
  // is no longer being used by msg2:
  msg1.~messaget();
  memset(msg1_storage, 0xff, sizeof(messaget));

  msg2.status() << "Test" << messaget::eom;

  CHECK(sstream1.str()=="");
  CHECK(sstream2.str()=="Test\n");
}

TEST_CASE("Assign a messaget")
{
  std::ostringstream sstream1, sstream2;
  stream_message_handlert handler1(sstream1), handler2(sstream2);

  messaget msg1(handler1);

  // Assign messaget:
  messaget msg2;
  msg2=msg1;

  // Change its handler:
  msg2.set_message_handler(handler2);

  msg2.status() << "Test" << messaget::eom;

  CHECK(sstream1.str()=="");
  CHECK(sstream2.str()=="Test\n");
}

TEST_CASE("Assign a messaget, with deletion of the old messaget")
{
  std::ostringstream sstream1, sstream2;
  stream_message_handlert handler1(sstream1), handler2(sstream2);

  char msg1_storage[sizeof(messaget)];
  // Placement-new msg1, storing it in msg1_storage.
  messaget &msg1=*new(msg1_storage) messaget(handler1);

  // Assign messaget:
  messaget msg2;
  msg2=msg1;

  // Change its handler:
  msg2.set_message_handler(handler2);

  // Delete the old handler and trash its storage, to check that it
  // is no longer being used by msg2:
  msg1.~messaget();
  memset(msg1_storage, 0xff, sizeof(messaget));

  msg2.status() << "Test" << messaget::eom;

  CHECK(sstream1.str()=="");
  CHECK(sstream2.str()=="Test\n");
}
