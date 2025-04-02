
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
