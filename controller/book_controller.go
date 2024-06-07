package controller

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/a-h/templ"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/grepvenancio/biblioteca/model"
	"github.com/grepvenancio/biblioteca/view"
)

func Home(c *gin.Context) {
	component := view.HomePage()
	render(c, component, 200)
}

func InsertBookGet(c *gin.Context) {
	var book model.Book
	var ve map[string]string
	component := view.InsertBookPage(book, ve)
	render(c, component, 200)
}

func GetBook(c *gin.Context) {
	store := c.MustGet("store").(*model.MemoryStore)
	bookIsbn := c.Param("bookIsbn")
	book, ok := store.GetBook(bookIsbn)
	if !ok {
		http.NotFound(c.Writer, c.Request)
	}
	component := view.GetBookPage(*book)
	render(c, component, 200)
}

func BookIsbnGet(c *gin.Context) {
	var isbn struct {
		Isbn10 string `form:"isbn-10" binding:"required, isbn10"`
	}
	err := c.ShouldBind(&isbn)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			var errMsg string
			for _, fe := range ve {
				errMsg = getErrorMsg(fe)
			}
			component := view.IsbnInput(isbn.Isbn10, errMsg)
			render(c, component, 400)
			return
		}
	}
	component := view.IsbnInput(isbn.Isbn10, "")
	render(c, component, 200)
}

func UpdateBookGet(c *gin.Context) {
	store := c.MustGet("store").(*model.MemoryStore)
	isbn := c.Param("isbn")
	book, ok := store.GetBook(isbn)
	if !ok {
		http.NotFound(c.Writer, c.Request)
	}
	component := view.UpdateBookPage(*book, map[string]string{})
	render(c, component, 200)
}

func UpdateBookPut(c *gin.Context) {
	var book model.Book
	isbn := c.Param("isbn")
	err := c.ShouldBind(&book)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			out := make(map[string]string, len(ve))
			for _, fe := range ve {
				out[fe.Field()] = getErrorMsg(fe)
			}
			component := view.UpdateBookForm(book, out)
			render(c, component, 400, "outerHTML")
			return
		}
	}
	store := c.MustGet("store").(*model.MemoryStore)
	session := sessions.Default(c)
	session.AddFlash("Livro Atualizado!")
	session.Save()
	store.UpdateBook(isbn, book)
	location(c, "/books")
}

func DeleteBook(c *gin.Context) {
	store := c.MustGet("store").(*model.MemoryStore)
	isbn := c.Param("isbn")
	err := store.DeleteBook(isbn)
	session := sessions.Default(c)
	if err != nil {
		session.AddFlash("Livro não foi encontrado")
		session.Save()
		location(c, "/books")
		return
	}
	session.AddFlash("Livro removido dos registros")
	session.Save()
	location(c, "/books")
}

func GetAllBooks(c *gin.Context) {
	var path struct {
		Page  int    `form:"id" binding:"number, gte=0"`
		Query string `form:"q"`
	}
	store := c.MustGet("store").(*model.MemoryStore)
	err := c.ShouldBindUri(&path)
	if err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			var err string
			for _, fe := range ve {
				err = getErrorMsg(fe)
			}
			component := view.ErrorMessageBox(err)
			render(c, component, 400, "afterbegin")
		}
	}
	if path.Query != "" {
		var component templ.Component
		books, more := store.QueryBooks(path.Query, path.Page)
		if c.GetHeader("HX-Trigger") == "search" {
			component = view.BookRows(books, more, path.Page, path.Query)
		} else {
			component = view.GetAllBooksPage(
				books, path.Page, more, path.Query)
		}
		render(c, component, 200)
		return
	}
	books, more := store.GetAllBooks(path.Page)
	component := view.GetAllBooksPage(books, path.Page, more, path.Query)
	render(c, component, 200)
}

func BooksCountGet(c *gin.Context) {
	store := c.MustGet("store").(*model.MemoryStore)
	count := store.BooksCount()
	component := view.BookCounter(count)
	render(c, component, 200)
}

func InsertBookPost(c *gin.Context) {
	var book model.Book
	if err := c.ShouldBind(&book); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			err := make(map[string]string)
			for _, fe := range ve {
				err[fe.Field()] = getErrorMsg(fe)
			}
			component := view.InserBookForm(book, err)
			render(c, component, 200, "outerHTML")
			return
		}
	}
	store := c.MustGet("store").(*model.MemoryStore)
	session := sessions.Default(c)
	store.InsertBook(book)
	session.AddFlash("livro registrado no banco")
	location(c, fmt.Sprintf("/books/%s", book.Isbn10))
}
