/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2013 Sebastien Vincent <sebastien.vincent@turnserver.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

/*
 * Copyright (C) 2006-2013 Sebastien Vincent.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * \file list.h
 * \brief Doubly linked list management.
 * \author Sebastien Vincent
 * \date 2006-2013
 */

#ifndef VSUTILS_LIST_H
#define VSUTILS_LIST_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(_MSC_VER) && !defined(__cplusplus)
/* Microsoft compiler does not know inline keyword in a pure C program */
#define inline __inline
#endif

#include <stddef.h> /* for offsetof */

/**
 * \struct list_head
 * \brief Doubly linked list implementation.
 *
 * Simple doubly linked list implementation inspired by include/linux/list.h.
 * \code
 * struct element
 * {
 *     int id;
 *     struct list_head list;
 * }
 *
 * struct list_head list;
 * struct list_head* tmp = NULL;
 * struct list_head* pos = NULL;
 * struct element* el = (struct element*)malloc(sizeof(struct element));
 * struct element* el2 = (struct element*)malloc(sizeof(struct element));
 * struct element* el3 = (struct element*)malloc(sizeof(struct element));
 *
 * if(!el || !el2 || !el3)
 * {
 *     free(el);
 *     free(el2);
 *     free(el3);
 *     return;
 * }
 *
 * el->id = 1;
 * el2->id = 2;
 * el3->id = 3;
 *
 * list_head_init(&list);
 * list_head_add_tail(&list, &el->list);
 * list_head_add_tail(&list, &el2->list);
 * list_head_add_tail(&list, &el3->list);
 *
 * fprintf(stdout, "Size: %u\n", list_head_size(&list));
 * list_head_iterate_safe(&list, pos, tmp)
 * {
 *     struct element* e = list_head_get(pos, struct element, list);
 *     fprintf(stdout, "Id: %d\n", e->id);
 * }
 * 
 * list_head_remove(&list, &el->list);
 * free(el);
 * fprintf(stdout, "Size: %u\n", list_head_size(&list));
 *
 * list_head_iterate_safe(&list, pos, tmp)
 * {
 *    struct element* e = list_head_get(pos, struct element, list);
 *    fprintf(stdout, "Id: %d\n", e->id);
 *    list_head_remove(&list, &e->list);
 *    free(e);
 * }
 * \endcode
 * \note To use it simply: VSUTILS_LIST_HEAD(name_variable) to declare the variable.
 */
struct list_head
{
  struct list_head *next; /**< Next element in the list. */
  struct list_head *prev; /**< Previous element in the list. */
};

/**
 * \def VSUTILS_LIST_HEAD
 * \brief Static initializer for a list head.
 * \param name the variable name to initialize.
 */
#define VSUTILS_LIST_HEAD(name) struct list_head name = {&name, &name}

/**
 * \def list_head_get
 * \brief Get the element.
 * \param item the list_head pointer item.
 * \param type the type of the struct this is embedded in.
 * \param member the name of the list_head struct within the struct.
 * \return pointer on the structure for this entry.
 */
#define list_head_get(item, type, member) \
  (type *)((char *)(item) - offsetof(type, member))

/**
 * \def list_head_iterate
 * \brief Iterate over a list.
 * \param list the list.
 * \param pos a struct list_head pointer to use as a loop counter.
 */
#define list_head_iterate(list, pos) \
  for((pos) = (list)->next ; (pos) != (list) ; (pos) = (pos)->next)

/**
 * \def list_head_iterate_safe
 * \brief Thread safe version to iterate over a list.
 * \param list the list.
 * \param pos a struct list_head pointer to use as loop counter.
 * \param n temporary variable.
 */
#define list_head_iterate_safe(list, pos, n) \
  for((pos) = (list)->next, (n) = (pos)->next ; (pos) != (list) ; \
      (pos) = (n), (n) = (pos)->next)

/**
 * \brief Initialize list.
 * \param list The list to initialize.
 */
static inline void list_head_init(struct list_head* list)
{
	list->prev = list;
	list->next = list;
}

/**
 * \brief Add a new entry after the specified list.
 * \param list the list.
 * \param item new entry to be added.
 * \note in case several entries are added in the same list, they will
 * be added in reverse order: 1, 2, 3 are added but iterate over the list will
 * show 3, 2, 1.
 */
static inline void list_head_add(struct list_head* list,
		struct list_head* item) 
{
	struct list_head* next = list->next;
	next->prev = item;
	item->next = next;
	item->prev = list;
	list->next = item;
}

/**
 * \brief Add a new entry before the specified head.
 * \param list the list.
 * \param item new entry to be added.
 * \note in case several entries are added in the same list, they will
 * be added in same order: 1, 2, 3 are added and iterate over the list will
 * show 1, 2, 3.
 */
static inline void list_head_add_tail(struct list_head* list,
		struct list_head* item)
{
	struct list_head* prev = list->prev;
	list->prev = item;
	item->next = list;
	item->prev = prev;
	prev->next = item;
}

/**
 * \brief Remove entry from list.
 * \param list the list.
 * \param item pointer of the element to remove from the list.
 * \note list_head_empty on item does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_head_remove(struct list_head* list,
		struct list_head* item)
{
	(void)list;
	item->next->prev = item->prev;
	item->prev->next = item->next;
	item->next = item;
	item->prev = item;
}

/**
 * \brief Return whether or not the list is empty.
 * \param list the list.
 * \return 1 if empty, 0 otherwise.
 */
static inline int list_head_is_empty(struct list_head* list)
{
	return list->next == list;
}

/**
 * \brief Get the number of element in the list.
 * \param list the list
 * \return size of the list
 */
static inline unsigned int list_head_size(struct list_head* list)
{
  struct list_head* lp = NULL;
  unsigned int size = 0;

  list_head_iterate(list, lp)
  {
    size++;
  }
  return size;
}

#endif /* VSUTILS_LIST_H */

