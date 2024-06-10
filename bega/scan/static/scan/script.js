// script.js


async function toggleCategoryData(categoryLine) {    
	const categoryDataBackground = categoryLine.nextElementSibling;
	const categoryData = categoryDataBackground.children[0];
	
	console.log(categoryDataBackground);
	
	
	if (categoryDataBackground.classList.contains("inactive-background")) {
		categoryDataBackground.classList.remove("inactive-background");
		categoryDataBackground.classList.add("active-backgound");
		categoryData.classList.remove("inactive");
		categoryData.classList.add("active");
	} else {
		categoryDataBackground.classList.remove("active-backgound");
		categoryDataBackground.classList.add("inactive-background");
		categoryData.classList.remove("active");
		categoryData.classList.add("inactive");
	}
	
	
	const img = categoryLine.querySelector("img");
	if (img.classList.contains("rotate")) {
		img.classList.remove("rotate");
	}
	else {
		img.classList.add("rotate");
	}
	
}


async function toggleIdCardService(element,type) {
	if (element.classList.contains("clickable-result")) {
	  const idDivData = element.closest(".id-div-data");
	  
	  var divData = null
	  

	  if(type == "https"){
	  	divData = idDivData.querySelector(".ip-card-service-goat");
	  }else if(type == "smtp"){
		divData = idDivData.querySelector(".ip-card-service-owl");
	  }



	  const divLine = idDivData.querySelector(".line-between-card");

	  if (divData.classList.contains("inactive")) {
		var allActive = idDivData.querySelectorAll(".active");
		for (var i = 0; i < allActive.length; i++) {
			allActive[i].classList.remove("active");
			allActive[i].classList.add("inactive");
		}

		divData.classList.remove("inactive");
		divLine.classList.remove("inactive");
		divData.classList.add("active");
		divLine.classList.add("active");

		
	  } else {
		divData.classList.remove("active");
		divData.classList.add("inactive");
		divLine.classList.remove("active");
		divLine.classList.add("inactive");
	  }
	  
	  
	}
  }


// Fonction pour gérer le clic sur une cellule du tableau
async function copyCellValue(event) {
	if (event.target.tagName == "TD") {
		const cellValue = event.target.textContent.trim();
		const textarea = document.createElement("textarea");
		textarea.value = cellValue;
		document.body.appendChild(textarea);
		textarea.select();
		document.execCommand("copy");
		document.body.removeChild(textarea);
		

		const copiedMessage = document.getElementById("copied-message");

		if(copiedMessage.classList.contains("inactive") ){

			copiedMessage.classList.remove("inactive");
			setTimeout(function(){
				console.log("coucou");
				copiedMessage.classList.add("inactive");}, 2000);
				
			
		}
	}
}
	
	
	
const table = document.getElementById("domainNameTable");
table.addEventListener("click", copyCellValue);
	
	

async function allowCopyValue(event) {
	console.log(event.textContent);
	const cellValue = event.textContent.trim();
	const textarea = document.createElement("textarea");
	textarea.value = cellValue;
	document.body.appendChild(textarea);
	textarea.select();
	document.execCommand("copy");
	document.body.removeChild(textarea);
	

	const copiedMessage = document.getElementById("copied-message");

	if(copiedMessage.classList.contains("inactive") ){

		copiedMessage.classList.remove("inactive");
		setTimeout(function(){
			copiedMessage.classList.add("inactive");}, 2000);
			
		
	}
}


	
async function toggLeakCard(idCard) {
	const allLeakCards = document.querySelectorAll(".leak-details-table");
	const leakCard = document.getElementById(idCard);
	const lineSeparator = document.getElementById("line-between-card-email");

	for (var i = 0; i < allLeakCards.length; i++) {
		if (allLeakCards[i].id != idCard) {
			allLeakCards[i].classList.remove("active");
			allLeakCards[i].classList.add("inactive");
		}
	}

	if (leakCard.classList.contains("inactive")) {
		leakCard.classList.remove("inactive");
		leakCard.classList.add("active");
		lineSeparator.classList.remove("inactive");
		lineSeparator.classList.add("active");
	} else {
		leakCard.classList.remove("active");
		leakCard.classList.add("inactive");
		lineSeparator.classList.remove("active");
		lineSeparator.classList.add("inactive");
	}
}


async function toggleCVECard(idCard) {
	const allLeakCards = document.querySelectorAll(".vulns-div-details");
	const leakCard = document.getElementById(idCard);
	const lineSeparator = document.getElementById("line-between-card-vulns");

	for (var i = 0; i < allLeakCards.length; i++) {
		if (allLeakCards[i].id != idCard) {
			allLeakCards[i].classList.remove("active");
			allLeakCards[i].classList.add("inactive");
		}
	}

	if (leakCard.classList.contains("inactive")) {
		leakCard.classList.remove("inactive");
		leakCard.classList.add("active");
		lineSeparator.classList.remove("inactive");
		lineSeparator.classList.add("active");
	} else {
		leakCard.classList.remove("active");
		leakCard.classList.add("inactive");
		lineSeparator.classList.remove("active");
		lineSeparator.classList.add("inactive");
	}
}