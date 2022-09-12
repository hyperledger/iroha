/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RADIX_TREE_HPP
#define IROHA_RADIX_TREE_HPP

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace iroha {

  /**
   * Determines the permitted symbols
   * [0-9]
   * [A-Z]
   * [a-z]
   * /
   * #
   * @
   */
  struct Alphabet {
    static constexpr uint32_t f0 = 'z' - '_' + 1ul;
    static constexpr uint32_t f1 = '9' - '-' + 1ul;
    static constexpr uint32_t f2 = 'Z' - '@' + 1ul;

    static uint32_t position(char d) {
      assert((d >= '_' && d <= 'z') || (d >= '-' && d <= '9')
             || (d >= '@' && d <= 'Z') || d == '#');

      return ((uint32_t)d - uint32_t('_')) < f0
          ? uint32_t(d) - uint32_t('_')
          : ((uint32_t)d - uint32_t('-')) < f1
              ? uint32_t(d) - uint32_t('-') + f0
              : ((uint32_t)d - uint32_t('@')) < f2
                  ? uint32_t(d) - uint32_t('@') + f0 + f1
                  : d == '#' ? f2 + f1 + f0 : (uint32_t)-1;
    }

    static bool allowed(char d) {
      return ((uint32_t)d - uint32_t('_')) < f0
          || ((uint32_t)d - uint32_t('-')) < f1
          || ((uint32_t)d - uint32_t('@')) < f2 || d == '#';
    }

    static constexpr uint32_t size() {
      return f2 + f1 + f0 + 1ul;
    }
  };

  template <typename Type,
            typename AlphabetT = Alphabet,
            typename CharT = char,
            uint32_t KeySz = 16ul,
            typename AllocT = std::allocator<char>>
  class RadixTree {
    struct NodeContext {
      NodeContext *parent;
      NodeContext *children[AlphabetT::size()];
      CharT key[KeySz];
      uint32_t children_count;
      uint32_t key_sz;

      NodeContext() : parent(nullptr), children_count(0ul), key_sz(0ul) {
        std::memset(key, 0, sizeof(key));
        std::memset(children, 0, sizeof(children));
      }
    };
    struct Node {
      NodeContext context;
      std::optional<Type> data;

      template <typename... Args>
      explicit Node(Args &&... args) : data(std::forward<Args>(args)...) {}
    };
    static_assert(offsetof(Node, context) == 0ul,
                  "Context must be with 0 offset.");
    using Alloc =
        typename std::allocator_traits<AllocT>::template rebind_alloc<Node>;
    using AllocStr =
        typename std::allocator_traits<AllocT>::template rebind_alloc<CharT>;

    mutable NodeContext root_;
    std::basic_string<CharT, std::char_traits<CharT>, AllocStr> key_name_;
    Alloc alloc_;

    template <typename... Args>
    Node *allocate(Args &&... args) {
      auto ptr = (Node *)alloc_.allocate(1);
      return new (ptr) Node(std::forward<Args>(args)...);
    }

    void deallocate(Node *node) {
      node->~Node();
      alloc_.deallocate(node, 1);
    }

    template <typename... Args>
    Node *create(CharT const *key, uint32_t len, Args &&... args) {
      Node *const created = allocate(std::forward<Args>(args)...);
      memcpy(created->context.key, key, len * sizeof(CharT));
      created->context.key_sz = len;
      return created;
    }

    template <typename... Args>
    Node *reinit(Node *const what, Args &&... args) const {
      what->data.template emplace(std::forward<Args>(args)...);
      return what;
    }

    void createNodeKey(NodeContext const *const from) {
      key_name_.clear();
      auto parent = from;
      while (parent != &root_) {
        key_name_.insert(
            key_name_.begin(), parent->key, parent->key + parent->key_sz);
        parent = parent->parent;
      }
    }

    NodeContext *&getFromKey(NodeContext *const parent,
                             CharT const *key) const {
      return parent->children[AlphabetT::position(key[0ul])];
    }

    NodeContext *&getFromKey(Node *const parent, CharT const *key) const {
      return getFromKey(nodeToNodeContext(parent), key);
    }

    void chain(NodeContext *const what, NodeContext *const parent) {
      assert(what->key_sz != 0ul);
      getFromKey(parent, what->key) = what;
      what->parent = parent;
    }

    void unchain(NodeContext *const what) {
      assert(what->children_count == 0ul);

      assert(what->key_sz != 0ul);
      getFromKey(what->parent, what->key) = nullptr;

      assert(what->parent->children_count > 0ul);
      --what->parent->children_count;
    }

    void chain(Node *const what, Node *const where) {
      chain(nodeToNodeContext(what), nodeToNodeContext(where));
    }

    void chain(NodeContext *const what, Node *const where) {
      chain(what, nodeToNodeContext(where));
    }

    void chain(Node *const what, NodeContext *const where) {
      chain(nodeToNodeContext(what), where);
    }

    void adjustKey(CharT const *&key,
                   CharT const *const end,
                   CharT const *&target,
                   CharT const *const target_end) const {
      while (key != end && target != target_end && *key == *target) {
        ++key;
        ++target;
      }
    }

    struct SearchContext {
      NodeContext *node;

      char const *prefix_remains;
      uint32_t prefix_remains_len;

      char const *target;
      char const *target_begin;
      char const *target_end;
    };

    void findNearest(NodeContext *const from,
                     CharT const *&key,
                     uint32_t len,
                     SearchContext &sc) const {
      CharT const *const end = key + len;
      sc.node = from;
      sc.target = nullptr;
      sc.target_end = nullptr;
      sc.target_begin = nullptr;

      while (key != end)
        if (NodeContext *child = getFromKey(sc.node, key)) {
          sc.target = child->key;
          sc.target_begin = child->key;
          sc.target_end = child->key + child->key_sz;
          if (adjustKey(key, end, sc.target, sc.target_end);
              0ul == sc.target_end - sc.target)
            sc.node = child;
          else
            break;
        } else
          break;

      sc.prefix_remains = key;
      sc.prefix_remains_len = end - key;
    }

    Node *nodeContextToNode(NodeContext *const context) const {
      assert(context != &root_);
      return (Node *)context;
    }

    NodeContext *nodeToNodeContext(Node *const node) const {
      return &node->context;
    }

    NodeContext *getFirstChild(NodeContext const *const from) {
      assert(from->children_count != 0ul);
      for (auto &child : from->children)
        if (child != nullptr)
          return child;
      return nullptr;
    }

    NodeContext *getChildAfter(NodeContext const *const node,
                               NodeContext const *const target = nullptr) {
      if (!target)
        return (node->children_count > 0) ? getFirstChild(node) : nullptr;

      assert(target->parent == node);
      assert(target->key_sz > 0ul);

      for (auto pos = AlphabetT::position(target->key[0ul]) + 1;
           pos < AlphabetT::size();
           ++pos) {
        auto const child = node->children[pos];
        if (child != nullptr)
          return child;
      }
      return nullptr;
    }

    bool compress(NodeContext *const parent,
                  NodeContext *const target,
                  NodeContext *const child) {
      if (child->key_sz + target->key_sz <= KeySz) {
        CharT tmp[KeySz];
        std::memcpy(tmp, target->key, target->key_sz * sizeof(CharT));
        std::memcpy(
            tmp + target->key_sz, child->key, child->key_sz * sizeof(CharT));
        std::memcpy(
            child->key, tmp, (target->key_sz + child->key_sz) * sizeof(CharT));
        child->key_sz += target->key_sz;
        chain(child, parent);
        child->parent = parent;
        deallocate(nodeContextToNode(target));
        return true;
      }
      return false;
    }

    void tryCompressDown(NodeContext *const target) {
      if (target != &root_ && !nodeContextToNode(target)->data
          && target->children_count == 1ull
          && compress(target->parent, target, getFirstChild(target))) {
      }
    }

    void tryCompressUp(NodeContext *const child) {
      while (child->parent && child->parent != &root_
             && child->parent->children_count == 1ull
             && !nodeContextToNode(child->parent)->data
             && compress(child->parent->parent, child->parent, child))
        ;
    }

    template <typename... Args>
    NodeContext *breakPath(NodeContext *const parent,
                           CharT const *target_key,
                           uint32_t middle_key_len,
                           uint32_t target_key_len,
                           Args &&... args) {
      assert(middle_key_len < target_key_len);

      Node *const middle =
          create(target_key, middle_key_len, std::forward<Args>(args)...);

      NodeContext *const target = getFromKey(parent, target_key);
      std::memcpy(target->key,
                  target->key + middle_key_len,
                  (target->key_sz - middle_key_len) * sizeof(CharT));

      target->key_sz -= middle_key_len;
      chain(target, middle);
      chain(middle, parent);

      ++middle->context.children_count;
      tryCompressDown(target);

      return nodeToNodeContext(middle);
    }

    template <typename... Args>
    NodeContext *processLeaf(SearchContext const &context, Args &&... args) {
      Node *const created = create(context.prefix_remains,
                                   std::min(context.prefix_remains_len, KeySz),
                                   std::forward<Args>(args)...);
      chain(&created->context, context.node);
      ++context.node->children_count;

      return nodeToNodeContext(created);
    }

    template <typename... Args>
    NodeContext *processMiddle(SearchContext const &context, Args &&... args) {
      return breakPath(context.node,
                       context.target_begin,
                       context.target - context.target_begin,
                       context.target_end - context.target_begin,
                       std::forward<Args>(args)...);
    }

    template <typename... Args>
    NodeContext *processBranch(SearchContext const &context, Args &&... args) {
      NodeContext *const base =
          breakPath(context.node,
                    context.target_begin,
                    context.target - context.target_begin,
                    context.target_end - context.target_begin,
                    std::nullopt);

      Node *const created = create(context.prefix_remains,
                                   std::min(context.prefix_remains_len, KeySz),
                                   std::forward<Args>(args)...);

      chain(created, base);
      ++base->children_count;

      tryCompressUp(base);
      return nodeToNodeContext(created);
    }

    NodeContext *safeDelete(NodeContext *node) {
      NodeContext *const parent = node->parent;
      unchain(node);
      deallocate(nodeContextToNode(node));
      return parent;
    }

    void eraseWithChildren(NodeContext *const from) {
      NodeContext *node = from;
      NodeContext *const parent = from->parent;
      while (node != parent)
        node = (node->children_count != 0ul)
            ? getFirstChild(node)
            : (node != &root_) ? safeDelete(node) : node->parent;

      if (node && node != &root_) {
        while (canSafeDelete(node)) node = safeDelete(node);
        tryCompressUp(node);
        tryCompressDown(node);
      }
    }

    bool canSafeDelete(NodeContext *node) {
      return node != &root_ && node->children_count == 0ull
          && !nodeContextToNode(node)->data;
    }

   public:
    RadixTree() = default;
    explicit RadixTree(AllocT &alloc) : alloc_(alloc), key_name_(alloc_) {}

    ~RadixTree() {
      eraseWithChildren(&root_);
    }

    template <typename... Args>
    void insert(CharT const *key, uint32_t len, Args &&... args) {
      SearchContext context;
      NodeContext *from = &root_;
      CharT const *const end = key + len;

      do {
        findNearest(from, key, end - key, context);
        auto const target_remains_len = context.target_end - context.target;

        from = (context.prefix_remains_len == 0ul && target_remains_len == 0ul)
            ? context.node
            : (target_remains_len == 0ull) ? processLeaf(context, std::nullopt)
                                           : (context.prefix_remains_len == 0ul)
                    ? processMiddle(context, std::nullopt)
                    : processBranch(context, std::nullopt);

        key += std::min(context.prefix_remains_len, KeySz);
      } while (key != end);

      reinit(nodeContextToNode(from), std::forward<Args>(args)...);
    }

    Type *find(CharT const *key, uint32_t len) const {
      SearchContext context;
      findNearest(&root_, key, len, context);
      auto const target_remains_len = context.target_end - context.target;

      if (context.prefix_remains_len == 0ul && target_remains_len == 0ul)
        if (Node *const node = nodeContextToNode(context.node); node->data)
          return &(*node->data);

      return nullptr;
    }

    uint32_t erase(CharT const *key, uint32_t len) {
      SearchContext context;
      findNearest(&root_, key, len, context);

      auto const target_remains_len = context.target_end - context.target;
      if (context.prefix_remains_len == 0ul && target_remains_len == 0ul) {
        NodeContext *node = context.node;
        uint32_t const result = nodeContextToNode(node)->data ? 1ull : 0ull;
        if (node->children_count)
          nodeContextToNode(node)->data.reset();
        else
          do {
            node = safeDelete(node);
          } while (canSafeDelete(node));

        tryCompressUp(node);
        tryCompressDown(node);
        return result;
      }
      return 0ul;
    }

    void filterDelete(CharT const *key, uint32_t len) {
      SearchContext context;
      findNearest(&root_, key, len, context);

      if (context.prefix_remains_len == 0ul) {
        auto const target_remains_len = context.target_end - context.target;
        if (target_remains_len == 0ul)
          eraseWithChildren(context.node);
        else
          eraseWithChildren(getFromKey(context.node, context.target_begin));
      }
    }

    template <typename Func>
    void filterEnumerate(CharT const *key, uint32_t len, Func &&func) {
      SearchContext context;
      findNearest(&root_, key, len, context);

      if (context.prefix_remains_len == 0ul) {
        auto const target_remains_len = context.target_end - context.target;
        NodeContext *const from = (target_remains_len == 0ul)
            ? context.node
            : getFromKey(context.node, context.target_begin);
        createNodeKey(from);

        NodeContext *child = nullptr;
        NodeContext *node = from;

        do {
          while ((child = getChildAfter(node, child))) {
            node = child;
            child = nullptr;
            key_name_.append(node->key, node->key_sz);
          }
          if (node != &root_) {
            if (Node *const n = nodeContextToNode(node); n->data)
              std::forward<Func>(func)(
                  std::string_view(key_name_.data(), key_name_.size()),
                  &(*n->data));
            key_name_.resize(key_name_.size() - node->key_sz);
          }
          child = node;
          node = node->parent;
        } while (child != from);
      }
    }
  };

}  // namespace iroha
#endif  // IROHA_RADIX_TREE_HPP
