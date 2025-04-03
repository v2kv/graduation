
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
// Function to remove item from cart and update UI dynamically
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
          updateTotalPrice(data.total_price);

          // If cart is empty, show empty message
          if (data.cart_items.length === 0) {
              document.querySelector(".cart-content").innerHTML = "<p>Your cart is empty.</p>";
          }
      } else {
          alert("Error: " + data.error);
      }
  })
  .catch(error => console.error("Error removing item:", error));
}

// Function to update total price
function updateTotalPrice(newTotal) {
  document.querySelector(".total-price").textContent = `$${newTotal.toFixed(2)}`;
}

// Attach event listeners to remove buttons
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".remove-from-cart").forEach((button) => {
      button.addEventListener("click", function () {
          const cartItemId = this.dataset.cartItemId;
          removeCartItem(cartItemId);
      });
  });
});


// Call this function when items are added or removed from the cart
document.addEventListener("DOMContentLoaded", function () {
  updateCartTotal();  // Initial call to update total when page loads

  // Update total whenever an item is removed
  document.querySelectorAll(".remove-from-cart").forEach(button => {
      button.addEventListener("click", function () {
          const cartItemId = this.dataset.cartItemId;
          removeCartItem(cartItemId);
          updateCartTotal(); // Refresh total price after removing item
      });
  });
});
