package localserver

import "github.com/kataras/iris/v12"

func (s *server) signWithCertificate(ctx iris.Context) {

	renderPage(ctx, "signed", iris.Map{"message": string("body")})

}
