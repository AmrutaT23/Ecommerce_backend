
const multer = require("multer");
const path = require("path");
const express = require("express");
const cors = require("cors");
const db = require("./db");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();

// middleware
app.use(cors({
  origin: "http://localhost:5173",
  credentials: true
}));


app.use(express.json());
app.use("/upload", express.static("upload"));

app.use(session({
  name: "ecommerce_sid",
  secret: "secure-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: 1000 * 60 * 60 * 2,
  }
}));


function isAdmin(req, res, next) {
  if (!req.session || req.session.role !== "admin") {
    return res.status(403).json({ message: "Admin only access" });
  }
  next();
}


// test route
app.get("/", (req, res) => {
  res.send("Server is running");
});

/* ================= SIGNUP ================= */
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });

      if (result.length > 0) {
        return res.status(409).json({ message: "User already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.query(
        "INSERT INTO users (email, password) VALUES (?,?)",
        [email, hashedPassword],
        (err) => {
          if (err) return res.status(500).json({ message: "DB error" });

          res.status(201).json({ message: "Signup successful" });
        }
      );
    }
  );
});

/* ================= LOGIN ================= */
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });

      if (result.length === 0) {
        return res.status(401).json({ message: "Invalid email" });
      }

      const user = result[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(401).json({ message: "Invalid password" });
      }
      req.session.userId = user.id;
      req.session.role = user.role;

      res.json({
        message: "Login successful",
        user: { id: user.id, email: user.email },
        role: user.role,
      });
    }
  );
});

app.get("/log-auth", (req, res) => {
  if (req.session.userId) {
    res.json({
      loggedIn: true,
      user_id: req.session.userId,
    })
  } else {
    res.json({ loggedIn: false })
  }
})
/* ================= LOGOUT================= */

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("ecommerce_sid");
    res.json({ message: "Logged out" });
  });
});


// ================= PRODUCT ================
app.get("/products", (req, res) => {
  db.query(
    `
    SELECT 
      p.id,
      p.name,
      p.price,
      p.specs,
      p.description,
      p.status,
      c.name AS category,
      pi.image_url AS image
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    LEFT JOIN product_images pi 
      ON p.id = pi.product_id AND pi.is_primary = 1
    WHERE p.status = 'active'
    `,
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "DB error" });
      }
      res.json(rows);
    }
  );
});

app.get("/product-images/:productId", (req, res) => {
  const { productId } = req.params;
  db.query(
    "SELECT * FROM product_images WHERE product_id = ?",
    [productId],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "DB error" });
      res.json(rows);
    }
  );
});


// ================= CART ===================
app.post("/cart", (req, res) => {
  const user_id = req.session.userId;
  const { product_id } = req.body;
  // console.log("BODY:", req.body, user_id);

  if (!user_id || !product_id) {
    return res.status(400).json({ message: "userId and productId required" });
  }

  db.query(
    "SELECT * FROM cart WHERE user_id=? AND product_id=?",
    [user_id, product_id],
    (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });

      if (result.length > 0) {
        db.query(
          "UPDATE cart SET quantity = quantity + 1 WHERE id = ?",
          [result[0].id],
          err => {
            if (err) return res.status(500).json({ message: "DB error" });
            res.json({ message: "Cart updated" });
          }
        );
      } else {
        db.query(
          "INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, 1)",
          [user_id, product_id],
          err => {
            if (err) return res.status(500).json({ message: "DB error" });
            res.json({ message: "Product added to cart" });
          }
        );
      }
    }
  );
});
// ================= GET USER CART ===================
app.get("/cart", (req, res) => {
  const user_id = req.session.userId;

  if (!user_id) {
    return res.status(401).json({ message: "Please login first" });
  }

  db.query(
    "SELECT product_id, quantity FROM cart WHERE user_id = ?",
    [user_id],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "DB error" });
      }
      res.json(results);
    }
  );
});

// ================= REMOVE FROM CART =================
app.delete("/cart/:productId", (req, res) => {
  const user_id = req.session.userId;
  const product_id = Number(req.params.productId);

  if (!user_id) {
    return res.status(401).json({ message: "Please login first" });
  }

  if (isNaN(product_id)) {
    return res.status(400).json({ message: "Invalid product ID" });
  }

  db.query(
    "DELETE FROM cart WHERE user_id = ? AND product_id = ?",
    [user_id, product_id],
    (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Product not found in cart" });
      }

      res.json({ message: "Product removed from cart" });
    }
  );
});

// ================ UPDATE CART QUANTITY =================
app.put("/cart/:productId", (req, res) => {
  const user_id = req.session.userId;
  const product_id = Number(req.params.productId);
  const { quantity } = req.body;

  if (!user_id) {
    return res.status(401).json({ message: "Please login first" });
  }

  if (!product_id || quantity < 1) {
    return res.status(400).json({ message: "Invalid data" });
  }

  db.query(
    "UPDATE cart SET quantity=? WHERE user_id=? AND product_id=?",
    [quantity, user_id, product_id],
    (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Product not found in cart" });
      }
      res.json({ message: "Quantity updated" });
    }
  );
});



// ================ PROFILE ==================

app.get("/profile", (req, res) => {
  const user_id = req.session.userId;
  if (!user_id) {
    return res.status(401).json({ message: "Login required" });
  }

  db.query(

    "SELECT email, name, phone, address, profile_image,role FROM users WHERE id=?",
    [user_id],
    (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });
      res.json(result[0]);
    }
  );
});

app.put("/profile", (req, res) => {
  const user_id = req.session.userId;
  const { name, phone, address, profile_image } = req.body;

  if (!user_id) {
    return res.status(401).json({ message: "Login required" });
  }

  db.query(
    `UPDATE users 
     SET name = ?, phone = ?, address = ?, profile_image = ?
     WHERE id = ?`,
    [name, phone, address, profile_image, user_id],
    (err) => {
      if (err) return res.status(500).json({ message: "DB error" });
      res.json({ message: "Profile updated successfully" });
    }
  );
});
// =======================image upload ========================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "upload/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });
app.post("/profile/upload", upload.single("image"), (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  if (!req.file) {
    return res.status(400).json({ message: "No image uploaded" });
  }

  const imageUrl = `http://localhost:5000/upload/${req.file.filename}`;

  db.query(
    "UPDATE users SET profile_image = ? WHERE id = ?",
    [imageUrl, req.session.userId],
    (err) => {
      if (err) {
        console.error("DB Error:", err);
        return res.status(500).json({ message: "DB error" });
      }

      res.json({
        message: "Image uploaded successfully",
        image: imageUrl
      });
    }
  );
});


// ==============ADMIN ================

app.get("/admin/dashboard", isAdmin, (req, res) => {
  res.json({ message: "Welcome Admin" });
});
// --> add product
app.post(
  "/admin/add-product",
  isAdmin,
  upload.array("images", 5),
  (req, res) => {
    console.log("REQ BODY:", req.body);
    console.log("Type of imageUrls:", typeof req.body.imageUrls);

    const {
      name,
      category_id,
      price,
      specs,
      description,
      status,
      primaryIndex,
      imageSource,
    } = req.body;

    
    let imageUrls = [];

    if (req.body.imageUrls) {
      try {
        
        if (typeof req.body.imageUrls === 'string' && req.body.imageUrls.startsWith('[')) {
          imageUrls = JSON.parse(req.body.imageUrls);
        }
        
        else if (Array.isArray(req.body.imageUrls)) {
          imageUrls = req.body.imageUrls;
        }
        
        else if (typeof req.body.imageUrls === 'string') {
          imageUrls = req.body.imageUrls.split(',').map(url => url.trim());
        }
      } catch (error) {
        console.error("Error parsing imageUrls:", error);
        return res.status(400).json({ message: "Invalid image URLs format" });
      }
    }

    console.log("Parsed imageUrls:", imageUrls);
    console.log("Is array?", Array.isArray(imageUrls));

    
    if (!name || !category_id || !price || !description || !status) {
      return res.status(400).json({ message: "All fields required" });
    }

    if (imageSource === "device" && (!req.files || req.files.length === 0)) {
      return res.status(400).json({ message: "Images required for device upload" });
    }

    if (imageSource === "url" && imageUrls.length === 0) {
      return res.status(400).json({ message: "Image URLs required" });
    }

    const primary = primaryIndex !== undefined ? parseInt(primaryIndex) : 0;

   
    db.query(
      `INSERT INTO products 
       (name, category_id, price, specs, description, status) 
       VALUES (?,?,?,?,?,?)`,
      [name, category_id, price, specs, description, status],
      (err, result) => {
        if (err) {
          console.error("Product insert error:", err);
          return res.status(500).json({ message: "DB error" });
        }

        const productId = result.insertId;
        console.log("New product ID:", productId);

        
        let imageQueries = [];

        if (imageSource === "device" && req.files) {
          imageQueries = req.files.map((file, index) => [
            productId,
            `/upload/${file.filename}`,
            index === primary ? 1 : 0,
          ]);
        }

        if (imageSource === "url" && imageUrls.length > 0) {
          imageQueries = imageUrls.map((url, index) => {
            
            const cleanUrl = url.trim().replace(/['"]/g, '');
            return [
              productId,
              cleanUrl,
              index === primary ? 1 : 0,
            ];
          });
        }

        console.log("Image queries:", imageQueries);

        if (imageQueries.length === 0) {
          return res.status(400).json({ message: "No images to insert" });
        }

      
        db.query(
          `INSERT INTO product_images 
           (product_id, image_url, is_primary) 
           VALUES ?`,
          [imageQueries],
          (err, result) => {
            if (err) {
              console.error("Image insert error:", err);
              return res.status(500).json({
                message: "Failed to insert images",
                error: err.message
              });
            }

            console.log("Images inserted:", result.affectedRows);

            res.status(201).json({
              message: "Product added successfully",
              productId: productId,
              imagesCount: imageQueries.length,
            });
          }
        );
      }
    );
  }
);

// --> get categories
app.get("/admin/categories", isAdmin, (req, res) => {
  db.query("SELECT id, name FROM categories", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "DB error" });
    }
    res.json(rows);
  });
});
// --> get users
app.get("/admin/users", isAdmin, (req, res) => {
  db.query("SELECT id,email,name,phone,address,profile_image,role FROM users", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "DB error" });
    }
    res.json(rows);

  })
})
// --> get all products
app.get("/admin/products", isAdmin, (req, res) => {
  db.query(
    `
    SELECT 
      products.id,
      products.name AS product_name,
      products.price,
      products.specs,
      products.status,
      products.category_id,
      categories.name AS category_name,
      product_images.image_url AS product_image
      
    FROM products
    LEFT JOIN categories 
      ON products.category_id = categories.id
    LEFT JOIN product_images 
      ON products.id = product_images.product_id
     AND product_images.is_primary = 1
     LIMIT 50; 
    `,
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "DB error" });
      }
      res.json(rows);
    }
  );
});
// fetch single product
app.get("/admin/products/:productId", isAdmin, (req, res) => {
  const productId = parseInt(req.params.productId, 10);

  db.query(
    `SELECT * FROM products WHERE id = ?`,
    [productId],
    (err, result) => {
      if (err) return res.status(500).json({ message: "DB error" });
      if (result.length === 0) return res.status(404).json({ message: "Product not found" });

      const product = result[0];

      db.query(
        `SELECT id, image_url, is_primary FROM product_images WHERE product_id=?`,
        [productId],
        (err, imgResult) => {
          if (err) return res.status(500).json({ message: "DB error" });

          // ✅ Only send one response
          res.json({
            ...product,
            images: imgResult
          });
        }
      );
    }
  );
});


// -->delete product
app.delete("/admin/products/:productId", isAdmin, (req, res) => {
  const productId = parseInt(req.params.productId, 10);

  if (!productId) {
    return res.status(400).json({ message: "Invalid product ID" });
  }

  // 1️⃣ Delete product images (NOT category)
  db.query(
    "DELETE FROM product_images WHERE product_id = ?",
    [productId],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "DB error (product images)" });
      }

      // 2️⃣ Delete product only
      db.query(
        "DELETE FROM products WHERE id = ?",
        [productId],
        (err, result) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ message: "DB error (product)" });
          }

          if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Product not found" });
          }

          res.json({ message: "Product deleted successfully" });
        }
      );
    }
  );
});
app.put(
  "/admin/products/:productId",
  isAdmin,
  upload.array("images", 5), 
  (req, res) => {
    const productId = parseInt(req.params.productId, 10);

    const {
      name,
      category_id,
      price,
      status,
      specs,
      description,
      uploadType,
      primaryIndex,
      imagesChanged,
      imageUrls
    } = req.body;

    if (!productId || !name || !category_id || !price) {
      return res.status(400).json({ message: "Required fields missing" });
    }

    // 1️⃣ Update product table
    const updateQuery = `
      UPDATE products
      SET name=?, category_id=?, price=?, status=?, specs=?, description=?
      WHERE id=?
    `;

    db.query(
      updateQuery,
      [name, category_id, price, status, specs, description, productId],
      (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: "DB error" });
        }

        // 2️⃣ If images NOT changed → stop here
        if (imagesChanged !== "true") {
          return res.json({ message: "Product updated (no image change)" });
        }

        
        db.query(
          "DELETE FROM product_images WHERE product_id=?",
          [productId],
          (err) => {
            if (err) {
              return res.status(500).json({ message: "Failed to delete images" });
            }

            
            let imageData = [];

            if (uploadType === "device" && req.files?.length > 0) {
              imageData = req.files.map((file, index) => [
                productId,
                `/uploads/${file.filename}`,
                index == primaryIndex ? 1 : 0
              ]);
            }

            if (uploadType === "url" && imageUrls) {
              const urls = JSON.parse(imageUrls);
              imageData = urls.map((url, index) => [
                productId,
                url,
                index == primaryIndex ? 1 : 0
              ]);
            }

            if (imageData.length === 0) {
              return res.json({ message: "Product updated" });
            }

            db.query(
              "INSERT INTO product_images (product_id, image_url, is_primary) VALUES ?",
              [imageData],
              (err) => {
                if (err) {
                  console.error(err);
                  return res.status(500).json({ message: "Failed to save images" });
                }

                res.json({ message: "Product & images updated successfully" });
              }
            );
          }
        );
      }
    );
  }
);




app.listen(5000, () => {
  console.log("Server running on port 5000");
});
