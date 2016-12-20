/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_ANSI_C_ANSI_C_LANGUAGE_H
#define CPROVER_ANSI_C_ANSI_C_LANGUAGE_H

/*! \defgroup gr_ansi_c ANSI-C front-end */

#include <util/language.h>

#include "ansi_c_parse_tree.h"

class symbolt;
class symbol_tablet;

/*! \brief TO_BE_DOCUMENTED
    \ingroup gr_ansi_c
*/
class ansi_c_languaget:public languaget
{
public:
  bool preprocess(
    std::istream &instream,
    const std::string &path,
    std::ostream &outstream) override;

  bool parse(
    std::istream &instream,
    const std::string &path) override;

  bool typecheck(
    symbol_tablet &symbol_table,
    const std::string &module) override;

  bool final(
    symbol_tablet &symbol_table) override;

  void show_parse(std::ostream &out) override;

  ~ansi_c_languaget() override;
  ansi_c_languaget() { }

  bool from_expr(
    const exprt &expr,
    std::string &code,
    const namespacet &ns) override;

  bool from_type(
    const typet &type,
    std::string &code,
    const namespacet &ns) override;

  bool type_to_name(
    const typet &type,
    std::string &name,
    const namespacet &ns) override;

  bool to_expr(
    const std::string &code,
    const std::string &module,
    exprt &expr,
    const namespacet &ns) override;

  languaget *new_language() override
  { return new ansi_c_languaget; }

  std::string id() const override { return "C"; }
  std::string description() const override { return "ANSI-C 99"; }
  std::set<std::string> extensions() const override;

  void modules_provided(std::set<std::string> &modules) override;

protected:
  virtual irep_idt generate_opaque_stub_body(
    symbolt &symbol,
    symbol_tablet &symbol_table) override;

  virtual parameter_symbolt build_stub_parameter_symbol(
    const symbolt &function_symbol,
    size_t parameter_index,
    const code_typet::parametert &parameter) override;

  ansi_c_parse_treet parse_tree;
  std::string parse_path;
};

languaget *new_ansi_c_language();

#endif // CPROVER_ANSI_C_ANSI_C_LANGUAGE_H
