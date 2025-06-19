using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ogani_master.dto;
using ogani_master.Models;

namespace ogani_master.Controllers
{
    public class ShopGridController : Controller
    {
        private readonly int numberOfSaleOffs = 6;
        private readonly int numberOfNewProduct = 6;
        private readonly int numberOfProduct = 12;
        public OganiMaterContext context;

        public ShopGridController(OganiMaterContext _context) {
            this.context = _context;
        }

        [HttpGet]
        public async Task<IActionResult> Index(QueryProduct? queryProduct)
        {
            // Lấy các sản phẩm giảm giá
            List<Product> saleOffs = await this.context.Products
                .OrderByDescending(p => p.CreatedDate)
                .Take(this.numberOfSaleOffs)
                .Include(p => p.Category)
                .Where(p => p.DiscountPrice != null)
                .ToListAsync();

            List<Product> listProducts;

            int countOfProducts = await this.context.Products.CountAsync();

            // Tính toán số lượng sản phẩm bỏ qua (skip)
            int skip = (queryProduct?.page ?? 1) - 1 * this.numberOfProduct;
            if (skip < 0) skip = 0; // Đảm bảo không có giá trị skip âm

            var query = this.context.Products
                .Skip(skip)
                .Take(this.numberOfProduct)
                .Where(p => p.DiscountPrice == null);

            if (queryProduct != null)
            {
                if (queryProduct.unit != null)
                {
                    query = query.Where(p => p.Unit == queryProduct.unit);
                }

                if (queryProduct.category != null)
                {
                    query = query.Where(p => p.CAT_ID == queryProduct.category);
                }
            }

            // Lấy danh sách sản phẩm
            listProducts = await query.Include(p => p.Category).ToListAsync();

            // Lấy các sản phẩm mới nhất
            List<Product> listNewProducts = await this.context.Products
                .OrderByDescending(p => p.CreatedDate)
                .Take(this.numberOfNewProduct)
                .ToListAsync();

            // Lấy danh sách các category
            List<Category> categories = await this.context.Categories.ToListAsync();

            // Kiểm tra và lấy giá trị min và max của giá sản phẩm
            decimal minPriceDb = 0;
            decimal maxPriceDb = 0;

            var productCount = await this.context.Products.CountAsync();
            if (productCount > 0)
            {
                minPriceDb = await this.context.Products.MinAsync(p => p.Price);
                maxPriceDb = await this.context.Products.MaxAsync(p => p.Price);
            }

            ViewBag.Settings = context.Settings.ToList();
            ViewBag.SaleOffs = saleOffs;
            ViewBag.ListProducts = listProducts;
            ViewBag.ListNewProduct = listNewProducts;
            ViewBag.Categories = categories;
            ViewBag.CategoryActive = queryProduct?.category;
            ViewBag.UnitActive = queryProduct?.unit;
            ViewBag.MinPrice = (int)minPriceDb;
            ViewBag.MaxPrice = (int)maxPriceDb;
            ViewBag.CountOfProducts = countOfProducts;
            ViewBag.CurrentPage = queryProduct?.page ?? 1;

            return View();
        }
    }
}
