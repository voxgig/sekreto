#include "Sekreto.hpp"

#include <algorithm>

namespace sekreto {

bool Ordered::has(const std::string& key) const {
  for (const auto& entry : pairs) {
    if (key == entry.first) return true;
  }
  return false;
}

std::optional<std::string> Ordered::get(const std::string& key) const {
  for (const auto& entry : pairs) {
    if (key == entry.first) return entry.second;
  }
  return std::nullopt;
}

void Ordered::set(const std::string& key, const std::string& value) {
  for (auto& entry : pairs) {
    if (key == entry.first) {
      entry.second = value;
      return;
    }
  }
  pairs.emplace_back(key, value);
}

std::string asciiupper(const std::string& text) {
  std::string out = text;
  for (char& ch : out) {
    if ('a' <= ch && 'z' >= ch) ch = static_cast<char>(ch - 32);
  }
  return out;
}

std::string asciilower(const std::string& text) {
  std::string out = text;
  for (char& ch : out) {
    if ('A' <= ch && 'Z' >= ch) ch = static_cast<char>(ch + 32);
  }
  return out;
}

std::vector<std::string> segments(const std::string& name) {
  std::vector<std::string> out;
  size_t start = 0;

  while (true) {
    size_t at = name.find('.', start);
    if (std::string::npos == at) {
      out.push_back(name.substr(start));
      return out;
    }
    out.push_back(name.substr(start, at - start));
    start = at + 1;
  }
}

// Scanned character by character rather than matched against
// `^[a-z0-9_]+$`: in most regex dialects `$` also matches before a final
// newline, so `api.token\n` would pass - and the spec pins that exact
// case, along with `api.token\r` and `api\n.token`.
bool validname(const std::string& name) {
  if (name.empty()) return false;

  for (const std::string& part : segments(name)) {
    if (part.empty()) return false;

    for (unsigned char ch : part) {
      bool ok = ('a' <= ch && 'z' >= ch) || ('0' <= ch && '9' >= ch) || '_' == ch;
      if (!ok) return false;
    }
  }

  return true;
}

bool validname(const Json& name) {
  if (!name.isstr()) return false;
  return validname(name.strval);
}

Name checkname(const std::string& name) {
  if (!validname(name)) {
    throw SekretoError("sekreto: invalid name: " + name);
  }
  return name;
}

Name checkname(const Json& name) {
  if (!validname(name)) {
    // Null and absent both render as the empty string, so the message ends
    // with a trailing space.
    std::string shown;
    if (!name.text(shown)) shown = "";
    throw SekretoError("sekreto: invalid name: " + shown);
  }
  return name.strval;
}

std::string envkey(const std::string& name, const std::string& prefix) {
  std::string checked = checkname(name);
  std::string flat;

  for (size_t index = 0; index < checked.size(); index++) {
    flat.push_back('.' == checked[index] ? '_' : checked[index]);
  }

  return prefix + asciiupper(flat);
}

VaultRef vaultref(const std::string& name) {
  std::vector<std::string> parts = segments(checkname(name));

  if (1 == parts.size()) {
    return VaultRef{parts[0], "value"};
  }

  std::string path;
  for (size_t index = 0; index + 1 < parts.size(); index++) {
    if (0 < index) path += "/";
    path += parts[index];
  }

  return VaultRef{path, parts[parts.size() - 1]};
}

std::string flatname(const std::string& name, const std::string& sep) {
  std::vector<std::string> parts = segments(checkname(name));

  std::string flat;
  for (size_t index = 0; index < parts.size(); index++) {
    if (0 < index) flat += sep;
    flat += parts[index];
  }

  if ("-" == sep) {
    for (char& ch : flat) {
      if ('_' == ch) ch = '-';
    }
  }

  return flat;
}

std::string awsparam(const std::string& name, const std::string& prefix) {
  std::string checked = checkname(name);

  std::string base = prefix;
  if (!base.empty() && '/' != base[0]) base = "/" + base;
  if (!base.empty() && '/' == base[base.size() - 1]) base = base.substr(0, base.size() - 1);

  std::string tail;
  for (const std::string& part : segments(checked)) {
    tail += "/" + part;
  }

  return base + tail;
}

namespace {

std::string trimtext(const std::string& text) {
  size_t start = 0;
  size_t stop = text.size();

  while (start < stop) {
    char ch = text[start];
    if (' ' == ch || '\t' == ch || '\n' == ch || '\r' == ch || '\f' == ch || '\v' == ch) {
      start++;
    } else {
      break;
    }
  }

  while (stop > start) {
    char ch = text[stop - 1];
    if (' ' == ch || '\t' == ch || '\n' == ch || '\r' == ch || '\f' == ch || '\v' == ch) {
      stop--;
    } else {
      break;
    }
  }

  return text.substr(start, stop - start);
}

/// Unescape a double-quoted `.env` value. An escape this does not know is
/// preserved whole - backslash and all - rather than swallowed, and a
/// trailing backslash is literal. A scan, not a chain of replacements,
/// because `\\n` is a literal backslash followed by an n.
std::string unescape(const std::string& text) {
  std::string out;
  size_t index = 0;

  while (index < text.size()) {
    if ('\\' == text[index] && index + 1 < text.size()) {
      char next = text[index + 1];
      index += 2;
      switch (next) {
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case '\\': out.push_back('\\'); break;
        case '"': out.push_back('"'); break;
        default:
          out.push_back('\\');
          out.push_back(next);
      }
    } else {
      out.push_back(text[index]);
      index++;
    }
  }

  return out;
}

}  // namespace

Ordered parsedotenv(const std::string& text) {
  Ordered out;

  size_t start = 0;

  while (start <= text.size()) {
    size_t at = text.find('\n', start);
    std::string rawline =
        (std::string::npos == at) ? text.substr(start) : text.substr(start, at - start);

    if (!rawline.empty() && '\r' == rawline[rawline.size() - 1]) {
      rawline = rawline.substr(0, rawline.size() - 1);
    }

    std::string line = trimtext(rawline);

    // A `#` INSIDE a value is not a comment; only a line that opens with
    // one is.
    if (!line.empty() && '#' != line[0]) {
      std::string body = line;
      if (0 == body.compare(0, 7, "export ")) {
        body = trimtext(body.substr(7));
      }

      size_t eq = body.find('=');

      // Both "no =" and "empty key" are skipped, silently, without
      // disturbing the lines around them.
      if (std::string::npos != eq && 0 < eq) {
        std::string key = trimtext(body.substr(0, eq));
        std::string value = trimtext(body.substr(eq + 1));

        if (2 <= value.size() && '"' == value[0] && '"' == value[value.size() - 1]) {
          value = unescape(value.substr(1, value.size() - 2));
        } else if (2 <= value.size() && '\'' == value[0] && '\'' == value[value.size() - 1]) {
          value = value.substr(1, value.size() - 2);
        }

        out.set(key, value);
      }
    }

    if (std::string::npos == at) break;
    start = at + 1;
  }

  return out;
}

Ordered parsedotenv(const Json& text) {
  if (!text.isstr()) return Ordered();
  return parsedotenv(text.strval);
}

std::string redact(const std::string& text, const std::vector<std::string>& values) {
  std::string out = text;

  // A COPY is sorted: `values` belongs to the caller (it is `seen` when
  // called through Sekreto::redact), and sorting in place would reorder the
  // live redaction history.
  //
  // Longest first, always: a shorter value that is a prefix of a longer one
  // would otherwise redact half of it and leave the rest in the log.
  // Stably, so two values of the same length are redacted in arrival order
  // rather than in an order that varies between runs.
  std::vector<std::string> usable;
  for (const std::string& value : values) {
    if (4 <= value.size()) usable.push_back(value);
  }

  std::stable_sort(usable.begin(), usable.end(),
                   [](const std::string& left, const std::string& right) {
                     return left.size() > right.size();
                   });

  for (const std::string& value : usable) {
    // A literal replace-all, never a regex: a secret containing regex
    // metacharacters must not be interpreted as a pattern.
    std::string next;
    size_t start = 0;

    while (true) {
      size_t at = out.find(value, start);
      if (std::string::npos == at) {
        next += out.substr(start);
        break;
      }
      next += out.substr(start, at - start);
      next += "[redacted]";
      start = at + value.size();
    }

    out = next;
  }

  return out;
}

std::string storename(const Provider& provider) {
  std::string text = provider.describe();
  size_t at = text.find(':');
  return (std::string::npos == at) ? text : text.substr(0, at);
}

Sekreto::Sekreto(std::vector<std::shared_ptr<Provider>> providers,
                 std::vector<std::string> names, bool docache)
    : docache_(docache) {
  for (size_t index = 0; index < providers.size(); index++) {
    std::string store = index < names.size() ? names[index] : "";
    // An empty name falls back to the provider's kind.
    if (store.empty()) store = storename(*providers[index]);
    entries_.push_back(Entry{store, providers[index]});
  }
}

std::string Sekreto::get(const Name& name) {
  std::optional<std::string> found = tryget(name);

  if (!found.has_value()) {
    throw SekretoError("sekreto: unknown secret: " + name);
  }

  return found.value();
}

std::optional<std::string> Sekreto::tryget(const Name& name) {
  return resolve("", name, entries_);
}

std::string Sekreto::getfrom(const std::string& store, const Name& name) {
  std::optional<std::string> found = tryfrom(store, name);

  if (!found.has_value()) {
    throw SekretoError("sekreto: unknown secret: " + store + ":" + name);
  }

  return found.value();
}

std::optional<std::string> Sekreto::tryfrom(const std::string& store, const Name& name) {
  std::vector<Entry> matching;

  for (const Entry& entry : entries_) {
    if (store == entry.store) matching.push_back(entry);
  }

  // Naming a store that is not in the chain is an error, not a miss:
  // `tryget` already means "this store may not have it", so it cannot also
  // mean "this store may not exist" without hiding a typo. Raised BEFORE
  // the name is validated.
  if (matching.empty()) {
    throw SekretoError("sekreto: unknown store: " + store);
  }

  return resolve(store, name, matching);
}

std::optional<std::string> Sekreto::resolve(const std::string& store, const Name& name,
                                            const std::vector<Entry>& useentries) {
  // The name is validated first: before the cache, and before any provider
  // is asked.
  checkname(name);

  if (docache_) {
    for (const Cached& hit : cache_) {
      if (store == hit.store && name == hit.name) return hit.value;
    }
  }

  for (const Entry& entry : useentries) {
    // A provider that throws is not caught: a store that could not answer
    // must not read as a store that does not hold the secret.
    std::optional<std::string> found = entry.provider->lookup(name);

    if (found.has_value()) {
      if (docache_) cache_.push_back(Cached{store, name, found.value()});
      seen_.push_back(found.value());
      return found;
    }
  }

  // A miss is never cached: the secret may arrive later.
  return std::nullopt;
}

bool Sekreto::has(const Name& name) { return tryget(name).has_value(); }

bool Sekreto::hasin(const std::string& store, const Name& name) {
  return tryfrom(store, name).has_value();
}

Ordered Sekreto::all(const std::vector<Name>& names) {
  Ordered out;

  for (const Name& name : names) {
    out.set(name, get(name));
  }

  return out;
}

std::vector<std::string> Sekreto::sources() const {
  std::vector<std::string> out;

  for (const Entry& entry : entries_) {
    out.push_back(entry.provider->describe());
  }

  return out;
}

std::vector<std::string> Sekreto::stores() const {
  std::vector<std::string> out;

  for (const Entry& entry : entries_) {
    bool seen = false;
    for (const std::string& already : out) {
      if (already == entry.store) seen = true;
    }
    if (!seen) out.push_back(entry.store);
  }

  return out;
}

std::string Sekreto::redact(const std::string& text) const {
  return sekreto::redact(text, seen_);
}

void Sekreto::refresh() { cache_.clear(); }

void Sekreto::close() {
  entries_.clear();
  cache_.clear();
}

std::string Sekreto::str() const {
  std::string out = "Sekreto { stores: [ ";
  std::vector<std::string> names = stores();

  for (size_t index = 0; index < names.size(); index++) {
    if (0 < index) out += ", ";
    out += names[index];
  }

  return out + " ] }";
}

Json Sekreto::tojson() const {
  std::vector<Json> names;

  for (const std::string& store : stores()) {
    names.push_back(Json::str(store));
  }

  return Json::obj({{"stores", Json::arr(names)}});
}

}  // namespace sekreto
