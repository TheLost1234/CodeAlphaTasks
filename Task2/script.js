document.addEventListener('DOMContentLoaded', function() {
    // Add quiz section to the page
    const trainingModule = document.querySelector('.training-module');
    
    const quizSection = document.createElement('div');
    quizSection.className = 'module-section quiz-section';
    quizSection.innerHTML = `
        <h2>Test Your Knowledge</h2>
        <div id="quiz-container"></div>
        <button id="submit-quiz" style="display: none;">Submit Quiz</button>
        <div id="quiz-results"></div>
    `;
    
    trainingModule.appendChild(quizSection);

    // Quiz questions
    const quizQuestions = [
        {
            question: "Which of the following is NOT a common sign of a phishing email?",
            options: [
                "Professional email design with correct grammar",
                "Urgent or threatening language",
                "Suspicious sender email address",
                "Requests for sensitive information"
            ],
            correct: 0
        },
        {
            question: "What should you do if you receive a suspicious email?",
            options: [
                "Click the links to verify them",
                "Reply asking if it's legitimate",
                "Forward it to your IT department/spam reporting",
                "Download attachments to check them"
            ],
            correct: 2
        },
        {
            question: "Which is the best password practice?",
            options: [
                "Use the same password everywhere",
                "Use complex passwords and a password manager",
                "Write passwords in a notebook",
                "Use simple memorable passwords"
            ],
            correct: 1
        }
    ];

    let currentQuestion = 0;
    let score = 0;

    // Function to display question
    function displayQuestion() {
        const quizContainer = document.getElementById('quiz-container');
        const question = quizQuestions[currentQuestion];

        const questionHTML = `
            <div class="quiz-question">
                <h3>${question.question}</h3>
                <div class="quiz-options">
                    ${question.options.map((option, index) => `
                        <div class="quiz-option" data-index="${index}">
                            ${option}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        quizContainer.innerHTML = questionHTML;

        // Add click handlers to options
        document.querySelectorAll('.quiz-option').forEach(option => {
            option.addEventListener('click', handleOptionClick);
        });
    }

    // Function to handle option selection
    function handleOptionClick(e) {
        const selectedIndex = parseInt(e.target.dataset.index);
        const question = quizQuestions[currentQuestion];

        // Remove previous selections
        document.querySelectorAll('.quiz-option').forEach(option => {
            option.classList.remove('correct', 'incorrect');
        });

        // Show result
        if (selectedIndex === question.correct) {
            e.target.classList.add('correct');
            score++;
        } else {
            e.target.classList.add('incorrect');
            document.querySelector(`[data-index="${question.correct}"]`).classList.add('correct');
        }

        // Disable further clicks
        document.querySelectorAll('.quiz-option').forEach(option => {
            option.removeEventListener('click', handleOptionClick);
        });

        // Move to next question after delay
        setTimeout(() => {
            currentQuestion++;
            if (currentQuestion < quizQuestions.length) {
                displayQuestion();
            } else {
                showResults();
            }
        }, 1500);
    }

    // Function to show final results
    function showResults() {
        const quizContainer = document.getElementById('quiz-container');
        const percentage = (score / quizQuestions.length) * 100;
        
        quizContainer.innerHTML = `
            <div class="quiz-results">
                <h3>Quiz Complete!</h3>
                <p>Your score: ${score}/${quizQuestions.length} (${percentage}%)</p>
                <button onclick="location.reload()">Try Again</button>
            </div>
        `;
    }

    // Start the quiz
    displayQuestion();

    // Add smooth scrolling for navigation
    document.querySelectorAll('nav a').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const section = document.querySelector(this.getAttribute('href'));
            section.scrollIntoView({ behavior: 'smooth' });
        });
    });
}); 