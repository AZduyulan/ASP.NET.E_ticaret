using System.Data.Entity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;


namespace ÖrnekSite.Entity
{
    public class DataInitializer : DropCreateDatabaseIfModelChanges<DataContext>
    {
        protected override void Seed(DataContext context)
        {
            var kategoriler = new List<Category>()
            {
                new Category() { Name = "KAMERA",Description ="KAMERA ÜRÜNLERİ"},
                new Category() { Name = "TELEFON",Description ="TELEFON ÜRÜNLERİ"},
                new Category() { Name = "bilgisayar",Description ="bilgisayar ürünleri"}
               
            };
            foreach (var kategori in kategoriler)
            {
                context.Categories.Add(kategori);
            }
            context.SaveChanges();

            var urunler = new List<Product>() 
            {
                new Product() { Name ="Canon",Description="Kamera ürünleri",Price=2500,Stock=125,IsHome=true,IsApproved=true,IsFeatured=false,Slider=true,CategoryId=1,Image="1.jpg"},
                new Product() { Name ="Asus",Description="Bilgisayar ürünleri",Price=2000,Stock=100,IsHome=true,IsApproved=true,IsFeatured=true,Slider=true,CategoryId=3,Image="2.jpg"},
                new Product() { Name ="Lenova",Description="Bilgisayar ürünleri",Price=3500,Stock=50,IsHome=false,IsApproved=true,IsFeatured=true,Slider=false,CategoryId=3,Image="3.jpg"},
                new Product() { Name ="Samsung 6S",Description="Telefon ürünleri",Price=4500,Stock=15,IsHome=true,IsApproved=true,IsFeatured=false,Slider=true,CategoryId=2,Image="4.jpg"}
            };
            foreach (var urun in urunler)
            {
                context.Products.Add(urun);
            }
            context.SaveChanges();

            base.Seed(context);
        }
    }
}