package controller

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/grepvenancio/biblioteca/errors"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/grepvenancio/biblioteca/utils"
	"github.com/grepvenancio/biblioteca/view"
	"github.com/grepvenancio/biblioteca/view/components"
)

func Home(w http.ResponseWriter, r *http.Request) {
	component := view.HomePage()
	component.Render(r.Context(), w)
}

func InsertBookGet(w http.ResponseWriter, r *http.Request) {
	var book model.Book
	var errors errors.FormError
	component := view.InsertBookPage(book, errors)
	component.Render(r.Context(), w)
}

func GetBook(w http.ResponseWriter, r *http.Request) {
	store := r.Context().Value("store").(*model.MemoryStore)
	bookIsbn := chi.URLParam(r, "bookIsbn")
	book, ok := store.GetBook(bookIsbn)
	if !ok {
		http.NotFound(w, r)
	}
	component := view.GetBookPage(*book)
	component.Render(r.Context(), w)
}

func BookIsbnGet(w http.ResponseWriter, r *http.Request) {
	store := r.Context().Value("store").(*model.MemoryStore)
	bookIsbn := r.URL.Query().Get("isbn")
	_, errors := utils.ParseBookForm(r)
	if _, ok := store.GetBook(bookIsbn); ok {
		errors["isbn"] = "isbn deve ser um valor unico."
	}
	inputField := components.InputField(components.InputFieldParams{
		FieldName:  "isbn",
		FieldValue: bookIsbn,
		InputLabel: "Isbn-13",
		InputType:  "text",
		InputAttr: templ.Attributes{
			"id":         "isbn-input",
			"hx-get":     "/books/get_by",
			"hx-target":  "closest p",
			"hx-trigger": "change, keyup delay:200ms changed",
		},
		ErrorMsg: errors["isbn"],
	})
	inputField.Render(r.Context(), w)
	return
}

func UpdateBookGet(w http.ResponseWriter, r *http.Request) {
	var err errors.FormError
	store := r.Context().Value("store").(*model.MemoryStore)
	bookIsbn := chi.URLParam(r, "bookIsbn")
	book, ok := store.GetBook(bookIsbn)
	if !ok {
		http.NotFound(w, r)
	}
	component := view.UpdateBookPage(*book, err)
	component.Render(r.Context(), w)
}

func UpdateBookPut(w http.ResponseWriter, r *http.Request) {
	bookIsbn := chi.URLParam(r, "bookIsbn")
	r.ParseForm()
	book, err := utils.ParseBookForm(r)
	if err != nil {
		component := view.UpdateBookPage(book, err)
		component.Render(r.Context(), w)
	}
	store := r.Context().Value("store").(*model.MemoryStore)
	session := r.Context().Value("session").(*scs.SessionManager)
	store.UpdateBook(bookIsbn, book)
	session.Put(r.Context(), "flash", "Livro Atualizado!")
	http.Redirect(
		w, r, fmt.Sprintf("/books/%s", book.Isbn), http.StatusSeeOther)
}

func DeleteBook(w http.ResponseWriter, r *http.Request) {
	store := r.Context().Value("store").(*model.MemoryStore)
	bookIsbn := chi.URLParam(r, "bookIsbn")
	err := store.DeleteBook(bookIsbn)
	session := r.Context().Value("session").(*scs.SessionManager)
	if err != nil {
		session.Put(r.Context(), "flash", "Livro não foi encontrado")
		w.WriteHeader(http.StatusBadRequest)
		GetAllBooks(w, r)
	}
	session.Put(r.Context(), "flash", "Livro removido dos registros")
	http.Redirect(
		w, r, "/books", http.StatusSeeOther)
}

func GetAllBooks(w http.ResponseWriter, r *http.Request) {
	var component templ.Component
	var hasMoreBooks bool
	var books []model.Book
	var page int
	store := r.Context().Value("store").(*model.MemoryStore)
	query := r.URL.Query().Get("q")
	pageStr := r.URL.Query().Get("page")
	pageNum, err := strconv.ParseInt(pageStr, 10, 0)
	if err != nil || pageNum <= 0 {
		page = 1
	} else {
		page = int(pageNum)
	}
	if query != "" {
		books, hasMoreBooks = store.QueryBooks(query, page)
		if r.Header.Get("HX-Trigger") == "search" {
			component = view.BookRows(books, hasMoreBooks, page, query)
		} else {
			component = view.GetAllBooksPage(books, page, hasMoreBooks, query)
		}
		component.Render(r.Context(), w)
		return
	}
	books, hasMoreBooks = store.GetAllBooks(page)
	component = view.GetAllBooksPage(books, page, hasMoreBooks, query)
	component.Render(r.Context(), w)
}

func BooksCountGet(w http.ResponseWriter, r *http.Request) {
	store := r.Context().Value("store").(*model.MemoryStore)
	booksCount := store.BooksCount()
	component := view.BookCounter(booksCount)
	component.Render(r.Context(), w)
}

func InsertBookPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	book, err := utils.ParseBookForm(r)
	if err != nil {
		component := view.InsertBookPage(book, err)
		component.Render(r.Context(), w)
		return
	}
	store := r.Context().Value("store").(*model.MemoryStore)
	session := r.Context().Value("session").(*scs.SessionManager)
	store.InsertBook(book)
	session.Put(r.Context(), "flash", "livro registrado no banco")
	http.Redirect(
		w, r, fmt.Sprintf("/books/%s", book.Isbn), http.StatusSeeOther)
}
