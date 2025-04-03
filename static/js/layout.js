// Showing and hiding the cart
const cartIcon = document.querySelector("#cart-icon");
const cart = document.querySelector(".cart");
const cartClose = document.querySelector("#cart-close");

// Open cart
cartIcon.addEventListener("click", () => {
  cart.classList.add("active");
});

// Close cart
cartClose.addEventListener("click", () => {
  cart.classList.remove("active");
});

// Cart functionality
document.addEventListener("DOMContentLoaded", function () {
  // Add event listeners for update-quantity buttons
  document.querySelectorAll(".update-quantity").forEach((button) => {
    button.addEventListener("click", function () {
      const cartItemId = this.dataset.cartItemId;
      const action = this.dataset.action;

      fetch(`/cart/update/${cartItemId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      })
        .then((response) => response.json())
        .then((data) => {
          // Ensure data contains the expected properties
          if (!data.quantity || !data.total_price || !data.cart_total) {
            throw new Error("Invalid response data");
          }

          // Update quantity and total price for the specific cart item
          const cartBox = this.closest(".cart-box");
          cartBox.querySelector(".quantity").textContent = data.quantity;
          cartBox.querySelector(".carttotal" + cartItemId).textContent = `$${data.total_price.toFixed(2)}`;
          updateCartTotal(data.cart_total);
          // Update overall cart total
          document.querySelector(".total-price").textContent = `$${data.cart_total.toFixed(2)}`;
        })
        .catch((error) => {
          console.log("Error updating quantity:", error);
        });
    });
  });

  // Attach event listeners to remove buttons
  document.querySelectorAll(".remove-from-cart").forEach((button) => {
    button.addEventListener("click", function () {
      const cartItemId = this.dataset.cartItemId;
      removeCartItem(cartItemId); // Remove the item from the cart
    });
  });
  
  // Update total when the page loads
  updateCartTotal();
});

// Function to remove item from cart using AJAX
function removeCartItem(cartItemId) {
  fetch(`/cart/remove/${cartItemId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" }
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      // Remove the specific cart item from the DOM
      const cartItemElement = document.querySelector(`[data-cart-item-id="${cartItemId}"]`).closest(".cart-box");
      cartItemElement.remove();

      // Update total price
      updateCartTotal(data.cart_total);

      // If cart is empty, show empty message
      if (data.cart_items.length === 0) {
        document.querySelector(".cart-content").innerHTML = "<p>Your cart is empty.</p>";
      }
    } else {
      console.error("Error removing item:", data.error);
    }
  })
  .catch(error => console.error("Error removing item:", error));
}

// Function to update total price
function updateCartTotal(newTotal) {
  // Use the new total price passed from the removeCartItem function or calculate it
  if (newTotal !== undefined) {
    document.querySelector(".total-price").textContent = `$${newTotal.toFixed(2)}`;
  } else {
    // If no new total is provided, recalculate the total based on the cart items
    let total = 0;
    document.querySelectorAll('.cart-content .cart-box').forEach(cartBox => {
      const quantity = parseInt(cartBox.querySelector('.quantity').textContent);
      const price = parseFloat(cartBox.querySelector('.cart-price').textContent.slice(1)); // Remove $
      total += quantity * price;
    });
    document.querySelector('.total-price').textContent = `$${total.toFixed(2)}`;
  }
}