
//Showing and hiding the cart
const carItcon = document.querySelector("#cart-icon");
const cart = document.querySelector(".cart");
const cartClose = document.querySelector("#cart-close");

//open cart
carItcon.addEventListener("click", () => {
  cart.classList.add("active");
});
//close cart
cartClose.addEventListener("click", () => {
    cart.classList.remove("active");
});
  
//cart functionality
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".update-quantity").forEach((button) => {
    button.addEventListener("click", function () {
      const cartItemId = this.dataset.cartItemId;
      const action = this.dataset.action;

      fetch(`/cart/update/${cartItemId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      })
        .then((response) => {
          if (!response.ok) {
            return response.json().then((err) => {
              throw err;
            });
          }
          return response.json();
        })
        .then((data) => {
          // Update quantity and total price for the specific cart item
          const cartBox = this.closest(".cart-box");
          cartBox.querySelector(".quantity").textContent = data.quantity;
          cartBox.querySelector(
            ".carttotal" + cartItemId
          ).textContent = `$${data.total_price.toFixed(2)}`;

          // Update overall cart total
          document.querySelector(
            ".total-price"
          ).textContent = `$${data.cart_total.toFixed(2)}`;
        })
        .catch((error) => {
          console.log(error.error || "Error updating quantity.");
        });
    });
  });
});
// Function to remove item from cart using AJAX
// Function to remove item from cart and update UI
// Function to remove item from cart and update UI
function removeCartItem(cartItemId) {
  fetch(`/cart/remove/${cartItemId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" }
  })
  .then(response => response.json())
  .then(data => {
      if (data.success) {
          // Update cart badge count
          document.getElementById("cart-badge").textContent = data.cart_count;

          // Re-render the cart dynamically
          updateCartUI(data.cart_items);
      } else {
          alert("Error: " + data.error);
      }
  })
  .catch(error => console.error("Error removing item:", error));
}

// Function to update cart UI dynamically
function updateCartUI(cartItems) {
  const cartContainer = document.querySelector(".cart-content");
  cartContainer.innerHTML = ""; // Clear cart before re-rendering

  if (cartItems.length === 0) {
      cartContainer.innerHTML = "<p>Your cart is empty.</p>";
      return;
  }

  cartItems.forEach(item => {
      const cartItemHTML = `
          <div id="cart-item-${item.cart_item_id}" class="cart-box">
              <img src="/static/${item.image_url}" alt="${item.name}" />
              
              <div class="cart-details">
                  <h2 class="cart-product-title">${item.name}</h2>
                  <span class="cart-price">$${item.price}</span>
                  
                  <div class="cart-quantity">
                      <button class="update-quantity" data-cart-item-id="${item.cart_item_id}" data-action="decrease">-</button>
                      <span class="quantity">${item.quantity}</span>
                      <button class="update-quantity" data-cart-item-id="${item.cart_item_id}" data-action="increase">+</button>
                  </div>

                  <span class="cart-total">Total $${item.total_price}</span>
              </div>

              <button class="remove-from-cart btn-nonestyle" data-cart-item-id="${item.cart_item_id}">
                  <i class="fa-solid fa-trash cart-remove"></i>
              </button>
          </div>
      `;
      cartContainer.insertAdjacentHTML("beforeend", cartItemHTML);
  });

  // Reattach event listeners for newly added remove buttons
  document.querySelectorAll(".remove-from-cart").forEach((button) => {
      button.addEventListener("click", function () {
          const cartItemId = this.dataset.cartItemId;
          removeCartItem(cartItemId);
      });
  });
}

// Attach event listeners when the page loads
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".remove-from-cart").forEach((button) => {
      button.addEventListener("click", function () {
          const cartItemId = this.dataset.cartItemId;
          removeCartItem(cartItemId);
      });
  });
});

// Function to update counters dynamically
function updateCounters() {
  fetch("/api/counters")
  .then(response => response.json())
  .then(data => {
      document.getElementById("cart-badge").textContent = data.cart_count;
  })
  .catch(error => console.error("Error updating counters:", error));
}

  // Function to update counters dynamically
  function updateCounters() {
      fetch("/api/counters")
      .then(response => response.json())
      .then(data => {
          document.getElementById("cart-badge").textContent = data.cart_count;
      })
      .catch(error => console.error("Error updating counters:", error));
  }
